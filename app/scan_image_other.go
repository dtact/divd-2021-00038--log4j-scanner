//go:build !windows

package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"fmt"
	"io"
	"sync/atomic"
	"time"

	"os"

	kaniko_config "github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/image/remote"

	cli "github.com/urfave/cli/v2"

	"github.com/fatih/color"
	_ "github.com/op/go-logging"
)

func (b *fuzzer) ScanImage(ctx *cli.Context) error {
	ch := make(chan interface{})
	defer close(ch)

	b.writer.Start()
	defer b.writer.Stop() // flush and stop rendering

	start := time.Now()
	go func() {
		for {
			sub := time.Now().Sub(start)

			select {
			case <-ch:
				return
			default:
			}

			i := b.stats.Layers()

			fmt.Fprintf(b.writer, color.GreenString("[ ] Checked %d layers in %02.fh%02.fm%02.fs. \u001b[0K\n", atomic.LoadUint64(&i), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds()))
			time.Sleep(time.Millisecond * 100)
		}
	}()

	platform := "linux/amd64"

	for _, target := range b.targetPaths {
		image, err := remote.RetrieveRemoteImage(target, kaniko_config.RegistryOptions{}, platform)
		if err != nil {
			return err
		}

		layers, err := image.Layers()
		if err != nil {
			return err
		}

		for _, layer := range layers {
			digest, err := layer.Digest()
			if err != nil {
				return err
			}

			name := digest.Hex

			if b.verbose {
				fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][ ] Scanning layer %s \u001b[0K", name))
			}

			if err := func() error {
				// first write to temp fle, then add
				tf, err := os.CreateTemp("", "patch-")
				defer os.Remove(tf.Name())

				r, err := layer.Uncompressed()
				if err != nil {
					return err
				}

				size, _ := io.Copy(tf, r)

				// size, _ :=tf.Seek(0, io.SeekC)
				tf.Seek(0, io.SeekStart)

				r2, err := NewTARArchiveReader(tf, size)
				if err != nil {
					b.stats.IncError()
					fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][ ] could not open layer \u001b[0K", name))
					return err
				}

				if err := b.RecursiveFind(ctx, []string{}, []byte{}, r2); err != nil {
					fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not scan layer %s\u001b[0K\n", name))
				}

				return nil
			}(); err != nil {
				return err
			}

			b.stats.IncLayer()
		}

	}

	i := b.stats.Layers()
	sub := time.Now().Sub(start)
	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Scan finished! %d layers scanned, %d vulnerable files found, %d vulnerable libraries found, %d errors occured,  in %02.fh%02.fm%02.fs. \u001b[0K", i, b.stats.VulnerableFiles(), b.stats.VulnerableLibraries(), b.stats.Errors(), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds() ))
	return nil
}
