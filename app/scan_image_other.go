//go:build !windows

package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gobwas/glob"

	"os"

	cli "github.com/urfave/cli/v2"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/fatih/color"
	_ "github.com/op/go-logging"
)

// nocmp is an uncomparable struct. Embed this inside another struct to make
// it uncomparable.
//
//  type Foo struct {
//    nocmp
//    // ...
//  }
//
// This DOES NOT:
//
//  - Disallow shallow copies of structs
//  - Disallow comparison of pointers to uncomparable structs
type nocmp [0]func()

type AtomicString struct {
	_ nocmp // disallow non-atomic comparison

	v atomic.Value
}

var _zeroString string

// NewString creates a new String.
func NewAtomicString(val string) *AtomicString {
	x := &AtomicString{}
	if val != _zeroString {
		x.Store(val)
	}
	return x
}

// Load atomically loads the wrapped string.
func (x *AtomicString) Load() string {
	if v := x.v.Load(); v != nil {
		return v.(string)
	}
	return _zeroString
}

// Store atomically stores the passed string.
func (x *AtomicString) Store(val string) {
	x.v.Store(val)
}

type ImageError struct {
	error

	ID   string
	Name string
}

type ImageReader struct {
	io.ReadCloser
	ID   string
	Name string
}

func (b *fuzzer) ScanImage(ctx *cli.Context) error {
	if len(b.targetPaths) == 0 && !ctx.Bool("local") {
		return fmt.Errorf("No target paths set, nothing to do")
	}

	ch := make(chan interface{})
	defer close(ch)

	b.writer.Start()
	defer b.writer.Stop() // flush and stop rendering

	current := NewAtomicString("")

	start := time.Now()
	go func() {
		pause := false

		for {
			sub := time.Now().Sub(start)

			select {
			case v, ok := <-ch:
				if !ok {
					return
				}

				p, _ := v.(bool)
				pause = p
			default:
			}

			i := b.stats.Images()

			s := current.Load()

			if !pause {
				fmt.Fprintf(b.writer, color.GreenString("[ ] Currently scanning %s, checked %d images in %s. \u001b[0K\n", s, atomic.LoadUint64(&i), FormatDuration(sub)))
			}

			time.Sleep(time.Millisecond * 100)
		}
	}()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	work := make(chan interface{})

	if ctx.Bool("local") {
		images, err := cli.ImageList(ctx.Context, types.ImageListOptions{})
		if err != nil {
			return err
		}

		go func() {
			defer close(work)

			for _, image := range images {
				scan := len(b.targetPaths) == 0

				for _, target := range b.targetPaths {
					g := glob.MustCompile(target, ':', '/')

					if matched := g.Match(image.ID); matched {
						scan = scan || matched
					}

					if matched := strings.HasPrefix(image.ID, target); matched {
						scan = scan || matched
					}

					parts := strings.Split(image.ID, ":")
					if 2 > len(parts) {
					} else if matched := strings.HasPrefix(parts[1], target); matched {
						scan = scan || matched
					}

					if len(image.RepoTags) == 0 {
					} else if matched := g.Match(image.RepoTags[0]); matched {
						scan = scan || matched
					}

					if len(image.RepoTags) == 0 {
					} else if matched := strings.HasPrefix(target, image.RepoTags[0]); matched {
						scan = scan || matched
					}
				}

				name := "(none)"
				if len(image.RepoTags) > 0 {
					name = image.RepoTags[0]
				}

				if !scan {
					if b.debug {
						fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] Skipping image %s (%s) \u001b[0K", name, image.ID))
					}
					continue
				}

				if b.verbose {
					fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] Saving image %s (%s) \u001b[0K", name, image.ID))
				}

				r, err := cli.ImageSave(ctx.Context, []string{image.ID})
				if err != nil {
					work <- ImageError{
						error: err,
						Name:  name,
						ID:    image.ID,
					}
					continue
				}

				work <- ImageReader{
					ReadCloser: r,
					Name:       image.RepoTags[0],
					ID:         image.ID,
				}

			}
		}()
	} else {

		go func() {
			defer close(work)

			for _, target := range b.targetPaths {
				fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] Pulling image %s \u001b[0K", target))

				// pause status
				ch <- true

				// pull image
				status, err := cli.ImageCreate(ctx.Context, target, types.ImageCreateOptions{})
				if err != nil {
					work <- ImageError{
						error: err,
						Name:  target,
						ID:    "",
					}
					continue
				}

				decoder := json.NewDecoder(status)

				for decoder.More() {
					m := struct {
						Status string `json:"status"`
						Detail struct {
						} `json:"progressDetail"`
						Progress string `json:"progress"`
					}{}

					if err := decoder.Decode(&m); err != nil {
						work <- ImageError{
							error: fmt.Errorf("Could not json decode request: %w", err),
							Name:  target,
							ID:    target,
						}

						return
					}

					fmt.Fprintln(b.writer, color.WhiteString("[!][ ] %s: %s \u001b[0K", m.Status, m.Progress))
				}

				// resume status
				ch <- false

				r, err := cli.ImageSave(ctx.Context, []string{target})
				if err != nil {
					work <- ImageError{
						error: err,
						Name:  target,
						ID:    target,
					}
					continue
				}

				work <- ImageReader{
					ReadCloser: r,
					Name:       target,
					ID:         target,
				}

			}

		}()
	}

	for task := range work {
		if err, ok := task.(ImageError); ok {
			fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][ ] Could not scan image %s (%s): %s \u001b[0K", err.Name, err.ID, err.Error()))
			continue
		}

		image := task.(ImageReader)

		name := image.Name

		current.Store(fmt.Sprintf("%s (%s)", name, image.ID))

		fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] Scanning image %s (%s) \u001b[0K", image.Name, image.ID))

		if err := func() error {
			// first write to temp fle, then add
			tf, err := os.CreateTemp("", "image-")
			defer os.Remove(tf.Name())

			size, _ := io.Copy(tf, image)

			fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] scanning %s: %s (size=%d) \u001b[0K", name, tf.Name(), size))

			tf.Seek(0, io.SeekStart)

			r2, err := NewTARArchiveReader(tf, size)
			if err != nil {
				b.stats.IncError()
				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][ ] could not open layer \u001b[0K", name))
				return err
			}

			if err := b.RecursiveFind(ctx, BreadCrumbs{}.Add(fmt.Sprintf("%s (%s)", name, image.ID), nil), r2); err != nil {
				fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not scan layer %s\u001b[0K\n", name))
			}

			return nil
		}(); err != nil {
			return err
		}

		b.stats.IncImage()
	}

	i := b.stats.Images()
	sub := time.Now().Sub(start)

	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Scan finished! %d images scanned, %d vulnerable files found, %d vulnerable libraries found, %d errors occured, in %s. \u001b[0K", i, b.stats.VulnerableFiles(), b.stats.VulnerableLibraries(), b.stats.Errors(), FormatDuration(sub)))
	return nil
}
