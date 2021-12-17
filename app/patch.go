package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"time"

	"os"

	cli "github.com/urfave/cli/v2"

	"github.com/fatih/color"
	_ "github.com/op/go-logging"
)

func (b *fuzzer) RecursivePatch(ctx *cli.Context, w []string, h []byte, r ArchiveReader, aw ArchiveWriter) (bool, error) {
	patched := false

	// should check for hashes if vulnerable or not
	for v := range r.Walk() {
		if ae, ok := v.(ArchiveError); ok {
			fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not traverse into %s \u001b[0K", strings.Join(w, " -> "), ae.Error()))

			// failed to patch file
			return false, ae.Err
		}

		f := v.(ArchiveFile)

		if p, err := func() (bool, error) {
			size := f.FileInfo().Size()

			rc, err := f.Open()
			if err != nil {
				return false, err
			}

			defer rc.Close()

			// calculate hash
			shaHash256 := sha256.New()

			if _, err := io.Copy(shaHash256, rc); err != nil {
				b.stats.IncError()
				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not calculate hash \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
				return false, err
			}

			hash := shaHash256.Sum(nil)

			rc.Seek(0, io.SeekStart)

			// this function writes after patching the file back to the archive
			writeFunc := func(w ArchiveWriter, r io.Reader, size int64) error {
				switch af := f.(type) {
				case *ZIPArchiveFile:
					fh := af.FileHeader

					now := time.Now()

					// somehow the timezone is read incorrectly in golang zip lib, correct
					_, offset := now.Zone()
					fh.Modified = fh.Modified.Add(time.Duration(offset*-1) * time.Second)

					w, err := aw.Create(fh)
					if err != nil {
						return err
					}

					if _, err := io.Copy(w, r); err != nil {
						return err
					}

					return w.Close()
				case *DirectoryFile:
					// upper level we'll create patch files
					w, err := os.OpenFile(fmt.Sprintf("%s.patch", f.Name()), os.O_CREATE|os.O_WRONLY|os.O_EXCL, f.FileInfo().Mode().Perm())
					if err != nil {
						return err
					}

					if _, err := io.Copy(w, r); err != nil {
						return err
					}

					return w.Close()
				case *TARArchiveFile:
					th := *af.Header

					// adjust size
					th.Size = size

					w, err := aw.Create(th)
					if err != nil {
						return err
					}

					if _, err := io.Copy(w, r); err != nil {
						return err
					}

					return w.Close()
				default:
					panic(fmt.Sprintf("Unsupported type: %s", reflect.TypeOf(f)))
				}
			}

			if f.FileInfo().IsDir() {
				// we don't have to do anything with dirs
			} else {
				// check file
				if 4 > size {
					return false, writeFunc(aw, rc, f.FileInfo().Size())
				}

				data := []byte{0, 0, 0, 0}
				if _, err := rc.Read(data); err != nil {
					b.stats.IncError()
					fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not read magic from file \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
					return false, err
				}

				rc.Seek(0, io.SeekStart)

				// check for PK signature
				if bytes.Compare(data[0:4], []byte{0x50, 0x4B, 0x03, 0x04}) == 0 {
					// zip file
					r2, err := NewZipArchiveReader(NewUnbufferedReaderAt(rc), size)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open zip file for reading \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
						return false, err
					}

					// first write to temp fle, then add
					tf, err := os.CreateTemp("", "patch-")
					defer os.Remove(tf.Name())

					w2, err := NewZipArchiveWriter(tf)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open zip file for writing \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
						return false, err
					}

					patched, err := b.RecursivePatch(ctx, append(w, f.Name()), hash, r2, w2)
					if err != nil {
						return false, err
					}

					if err := w2.Close(); err != nil {
						return false, err
					}

					// seek to start
					size, err := tf.Seek(0, io.SeekCurrent)
					if err != nil {
						return false, err
					}

					tf.Seek(0, io.SeekStart)

					// we only write the file if it is patched, otherwise we'll just write the original file
					if patched {
						if b.verbose {
							fmt.Fprintln(b.writer.Bypass(), color.GreenString("[!][%s] patched %s \u001b[0K", strings.Join(append(w, f.Name()), " -> "), f.Name()))
						}

						return patched, writeFunc(aw, tf, size)
					}
				} else if bytes.Compare(data[0:3], []byte{0x1F, 0x8B, 0x08}) == 0 {
					// tgz
					r2, err := NewGzipTARArchiveReader(NewUnbufferedReaderAt(rc), size)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open tar file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
						return false, err
					}

					// first write to temp fle, then add
					tf, err := os.CreateTemp("", "patch-")
					defer os.Remove(tf.Name())

					gw := gzip.NewWriter(tf)

					w2, err := NewTARArchiveWriter(gw)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open zip file for writing \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
						return false, err
					}

					patched, err := b.RecursivePatch(ctx, append(w, f.Name()), hash, r2, w2)
					if err != nil {
						return false, err
					}

					if err := w2.Close(); err != nil {
						return false, err
					}

					if err := gw.Close(); err != nil {
						return false, err
					}

					// seek to start
					size, err := tf.Seek(0, io.SeekCurrent)
					if err != nil {
						return false, err
					}

					tf.Seek(0, io.SeekStart)

					// we only write the file if it is patched, otherwise we'll just write the original file
					if patched {
						if b.verbose {
							fmt.Fprintln(b.writer.Bypass(), color.GreenString("[!][%s] patched %s \u001b[0K", strings.Join(append(w, f.Name()), " -> "), f.Name()))
						}
						return patched, writeFunc(aw, tf, size)
					}
				} else if found, _ := IsTAR(rc); found {
					// first write to temp fle, then add
					tf, err := os.CreateTemp("", "patch-")
					defer os.Remove(tf.Name())

					r2, err := NewTARArchiveReader(NewUnbufferedReaderAt(rc), size)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open tar file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
						return false, err
					}

					w2, err := NewTARArchiveWriter(tf)
					if err != nil {
						b.stats.IncError()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open zip file for writing \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
						return false, err
					}

					patched, err := b.RecursivePatch(ctx, append(w, f.Name()), hash, r2, w2)
					if err != nil {
						return false, err
					}

					if err := w2.Close(); err != nil {
						return false, err
					}

					// seek to start
					size, err := tf.Seek(0, io.SeekCurrent)
					if err != nil {
						return false, err
					}

					tf.Seek(0, io.SeekStart)

					// we only write the file if it is patched, otherwise we'll just write the original file
					if patched {
						if b.verbose {
							fmt.Fprintln(b.writer.Bypass(), color.GreenString("[!][%s] patched %s \u001b[0K", strings.Join(append(w, f.Name()), " -> "), f.Name()))
						}

						return patched, writeFunc(aw, tf, size)
					}
				}

				parts := strings.Split(path.Base(f.Name()), ".")
				if !strings.EqualFold(parts[0], "JndiLookup") {
					// not JndiLookup
				} else if bytes.Compare(data[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE}) != 0 /* class file */ {
					// not a class file
				} else {
					// todo(remco): we need to pass hashes, so we can keep log4j2
					// can we patch / replace log4j with 2.16?
					version := "unknown"
					if v, ok := b.signatures[string(h)]; ok {
						version = v
					}

					if !b.IsAllowList(h) {
						b.stats.IncVulnerableFile()
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] found JndiLookup class file with hash %x (version: %s) \u001b[0K", strings.Join(append(w, f.Name()), " -> "), h, version))

						if _, ok := v.(*DirectoryFile); ok {
							return true, os.Rename(f.Name(), fmt.Sprintf("%s.vulnerable", f.Name()))
						} else {
							// we are removing this file from the output
							return true, nil
						}
					}
				}
			}

			rc.Seek(0, io.SeekStart)

			if b.debug {
				fmt.Fprintln(b.writer.Bypass(), color.GreenString("[!][%s] writing %s \u001b[0K", strings.Join(append(w, f.Name()), " -> "), f.Name()))
			}

			// don't copy to files on fs, take shortcut
			if _, ok := v.(*DirectoryFile); ok {
				return false, nil
			}

			return false, writeFunc(aw, rc, f.FileInfo().Size())
		}(); err != nil {
			return false, err
		} else {
			patched = patched || p
		}
	}

	return patched, nil
}
func (b *fuzzer) Patch(ctx *cli.Context) error {
	if len(b.targetPaths) == 0 {
		return fmt.Errorf("No target paths set, nothing to do")
	}

	ch := make(chan interface{})
	defer close(ch)

	b.writer.Start()
	defer b.writer.Stop() // flush and stop rendering

	start := time.Now()
	for _, target := range b.targetPaths {
		if fi, err := os.Stat(target); err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not retrieve info %s: %s\u001b[0K\n", target, err))
			continue
		} else if fi.IsDir() {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Politely refusing to patch directories %s, try with a single file.\u001b[0K\n", target))
			continue
		}

		dr, err := NewDirectoryReader(target, b.excludeList)
		if err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not create directory reader %s: %s\u001b[0K\n", target, err))
			continue
		}

		dw, err := NewDirectoryWriter(target)
		if err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not create directory writer %s: %s\u001b[0K\n", target, err))
			continue
		}

		if patched, err := b.RecursivePatch(ctx, []string{}, []byte{}, dr, dw); err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not walk into %s: %s\u001b[0K\n", target, err))
		} else if patched {
			fmt.Fprintf(b.writer.Bypass(), color.GreenString("[✓] Successfully patched %s => %s\u001b[0K\n", target, fmt.Sprintf("%s.patch", target)))
			b.stats.IncPatched()
		}
	}

	i := b.stats.Patched()
	sub := time.Now().Sub(start)
	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Patch finished! %d files patched, %d vulnerable files found, %d vulnerable libraries found, %d errors occured, in %s, average rate is: %0.f files/min. \u001b[0K", i, b.stats.VulnerableFiles(), b.stats.VulnerableLibraries(), b.stats.Errors(), FormatDuration(sub), float64(i)/sub.Minutes()))
	return nil
}
