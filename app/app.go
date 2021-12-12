package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/gosuri/uilive"
	_ "github.com/op/go-logging"
)

type fuzzer struct {
	config

	writer *uilive.Writer
	output *writer

	dialer func(network, addr string) (net.Conn, error)

	cachePath string
	method    string

	allowList   []string
	targetHosts []string

	hosts []string

	proxyURL *url.URL

	template Template

	wordsCh chan string
}
type writer struct {
	f io.WriteCloser
	m sync.Mutex
}

func NewWriter(path string) (*writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &writer{
		f: f,
		m: sync.Mutex{},
	}, nil
}

func (w *writer) WriteLine(format string, args ...interface{}) {
	w.m.Lock()
	defer w.m.Unlock()

	fmt.Fprintln(w.f, fmt.Sprintf(format, args...))
}

func New(options ...OptionFn) (*fuzzer, error) {
	words := make(chan string)

	b := &fuzzer{
		wordsCh: words,
		config: config{
			suffixes: []string{},
		},
	}

	b.writer = uilive.New()

	for _, optionFunc := range options {
		if err := optionFunc(b); err != nil {
			return nil, err
		}
	}

	if len(b.targetHosts) == 0 {
		return nil, fmt.Errorf("No target hosts set, nothing to do")
	}

	go func() {
		defer close(words)

		for _, target := range b.targetHosts {
			err := filepath.Walk(target, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not walk into %s: %s\u001b[0K\n", path, err))
					return nil
				}

				if info.IsDir() {
					return nil
				}

				words <- path
				return nil
			})

			if err != nil {
				fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not walk into %s: %s\u001b[0K\n", target, err))
				return
			}
		}

	}()

	return b, nil
}

type unbufferedReaderAt struct {
	R io.Reader
	N int64
}

func NewUnbufferedReaderAt(r io.Reader) io.ReaderAt {
	return &unbufferedReaderAt{R: r}
}

func (u *unbufferedReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < u.N {
		return 0, errors.New("invalid offset")
	}
	diff := off - u.N
	written, err := io.CopyN(ioutil.Discard, u.R, diff)
	u.N += written
	if err != nil {
		return 0, err
	}

	n, err = u.R.Read(p)
	u.N += int64(n)
	return
}

func (b *fuzzer) RecursiveFind(w []string, h string, r *zip.Reader) error {
	// should check for hashes if vulnerable or not
	for _, f := range r.File {
		if f.Name == "org/apache/logging/log4j/core/lookup/JndiLookup.class" {
			found := false
			for _, v := range b.allowList {
				if !strings.EqualFold(v, h) {
					continue
				}

				found = true
				break
			}

			if !found {
				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] found JndiLookup: [%s] with hash %s \u001b[0K", "FOUND", strings.Join(w, " -> "), h))
			}
		}

		func() error {
			rc, err := f.Open()
			if err != nil {
				return err
			}

			defer rc.Close()

			buff := bytes.NewBuffer([]byte{})

			h := sha256.New()

			size, err := io.Copy(buff, io.TeeReader(rc, h))
			if err != nil {
				return err
			}

			hash := fmt.Sprintf("%x", h.Sum(nil))

			// check for PK signature

			data := buff.Bytes()

			if bytes.Compare(data[0:2], []byte("PK")) != 0 {
				// not a zip
				return nil
			}

			br := bytes.NewReader(buff.Bytes())

			r2, err := zip.NewReader(br, size)
			if err != nil {
				return err
			}

			return b.RecursiveFind(append(w, f.Name), hash, r2)
		}()
	}

	return nil
}

func (b *fuzzer) Run() error {
	ch := make(chan interface{})
	defer close(ch)

	b.writer.Start()
	defer b.writer.Stop() // flush and stop rendering

	i := uint64(0)

	go func() {
		start := time.Now()
		for {
			sub := time.Now().Sub(start)

			select {
			case <-ch:
				return
			default:
			}

			fmt.Fprintf(b.writer, color.GreenString("[ ] Checked %d files in %02.fh%02.fm%02.fs, average rate is: %0.f req/min. \u001b[0K\n", atomic.LoadUint64(&i), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds(), float64(i)/sub.Minutes()))
			time.Sleep(time.Millisecond * 100)
		}
	}()

	for w := range b.wordsCh {
		if strings.HasSuffix(w, "org/apache/logging/log4j/core/lookup/JndiLookup.class") {
			fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] found JndiLookup: [%s]  \u001b[0K", "FOUND", w))
		}

		func() error {
			r, err := os.OpenFile(w, os.O_RDONLY, 0)
			if err != nil {
				return err
			}

			defer r.Close()

			buff := bytes.NewBuffer([]byte{})

			h := sha256.New()

			size, err := io.Copy(buff, io.TeeReader(r, h))
			if err != nil {
				return err
			}

			hash := fmt.Sprintf("%x", h.Sum(nil))

			// check for PK signature

			data := buff.Bytes()

			if bytes.Compare(data[0:2], []byte("PK")) != 0 {
				// not a zip
				return nil
			}

			r.Seek(0, io.SeekStart)

			r2, err := zip.NewReader(r, size)
			if err != nil {
				return err
			}

			return b.RecursiveFind([]string{w}, hash, r2)
		}()

		atomic.AddUint64(&i, 1)
	}

	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Scan finished! \u001b[0K"))
	return nil
}
