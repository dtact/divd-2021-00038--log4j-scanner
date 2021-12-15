package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"os"

	"github.com/fatih/color"
	"github.com/gosuri/uilive"
	_ "github.com/op/go-logging"
)

type fuzzer struct {
	config

	signatures map[string]string

	writer *uilive.Writer
	output *writer

	allowList [][]byte

	remoteHosts []string
	targetPaths []string

	stats Stats
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
	b := &fuzzer{
		config:     config{},
		signatures: map[string]string{},
	}

	b.writer = uilive.New()

	for k, v := range signatures {
		h, _ := hex.DecodeString(v)

		b.signatures[string(h)] = k
	}

	for _, optionFunc := range options {
		if err := optionFunc(b); err != nil {
			return nil, err
		}
	}

	if len(b.targetPaths) == 0 {
		return nil, fmt.Errorf("No target paths set, nothing to do")
	}

	return b, nil
}

var signatures = map[string]string{
	"2.0-alpha2": "bf4f41403280c1b115650d470f9b260a5c9042c04d9bcc2a6ca504a66379b2d6",
	"2.0-beta5":  "7d86841489afd1097576a649094ae1efb79b3147cd162ba019861dfad4e9573b",
	"2.0-beta2":  "ed285ad5ac6a8cf13461d6c2874fdcd3bf67002844831f66e21c2d0adda43fa4",
	"2.10.0":     "22b58febab566eddd5d4863f09dad4d5cc57677b6d4be745e3c6ce547124a66d",
	"2.9.1":      "dc435b35b5923eb05afe30a24f04e9a0a5372da8e76f986efe8508b96101c4ff",
	"2.14.1":     "ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0",
	"2.0-beta3":  "dbf88c623cc2ad99d82fa4c575fb105e2083465a47b84d64e2e1a63e183c274e",
	"2.0-beta4":  "a38ddff1e797adb39a08876932bc2538d771ff7db23885fb883fec526aff4fc8",
	"2.9.0":      "fb086e42c232d560081d5d76b6b9e0979e5693e5de76734cad5e396dd77278fd",
	"2.14.0":     "f04ee9c0ac417471d9127b5880b96c3147249f20674a8dbb88e9949d855382a8",
	"2.0.1":      "a00a54e3fb8cb83fab38f8714f240ecc13ab9c492584aa571aec5fc71b48732d",
	"2.8.2":      "10ef331115cbbd18b5be3f3761e046523f9c95c103484082b18e67a7c36e570c",
	"2.0":        "85338f694c844c8b66d8a1b981bcf38627f95579209b2662182a009d849e1a4c",
	"2.7":        "5bb84e110d5f18cee47021a024d358227612dd6dac7b97fa781f85c6ad3ccee4",
	"2.13.0":     "82e91afe0c5628b32ae99dd6965878402c668773fbd49b45b2b8c06a426c5bbb",
	"2.0-rc1":    "db3906edad6009d1886ec1e2a198249b6d99820a3575f8ec80c6ce57f08d521a",
	"2.6":        "df00277045338ceaa6f70a7b8eee178710b3ba51eac28c1142ec802157492de6",
	"2.1":        "8bdb662843c1f4b120fb4c25a5636008085900cdf9947b1dadb9b672ea6134dc",
	"2.8":        "ccf02bb919e1a44b13b366ea1b203f98772650475f2a06e9fac4b3c957a7c3fa",
	"2.6.2":      "cf65f0d33640f2cd0a0b06dd86a5c6353938ccb25f4ffd14116b4884181e0392",
	"2.13.1":     "88ebd503b35a0debe18c2707db9de33a8c6d96491270b7f02dd086b8072426b2",
	"2.4.1":      "42de36e61d454afff5e50e6930961c85b55d681e23931efd248fd9b9b9297239",
	"2.11.2":     "d4748cd5d8d67f513de7634fa202740490d7e0ab546f4bf94e5c4d4a11e3edbc",
	"2.0-alpha1": "006fc6623fbb961084243cfc327c885f3c57f2eba8ee05fbc4e93e5358778c85",
	"2.0-beta1":  "58e9f72081efff9bdaabd82e3b3efe5b1b9f1666cefe28f429ad7176a6d770ae",
	"2.12.0":     "8818f82570d3f509cfb27c209b9a8df6f188857b7462951a61a137be09cf3463",
	"2.0-beta6":  "4bfb0d5022dc499908da4597f3e19f9f64d3cc98ce756a2249c72179d3d75c47",
	"2.0-beta8":  "b3fae4f84d4303cdbad4696554b4e8d2381ad3faf6e0c3c8d2ce60a4388caa02",
	"2.0-beta9":  "dcde6033b205433d6e9855c93740f798951fa3a3f252035a768d9f356fde806d",
	"2.12.1":     "885e31a14fc71cb4849e93564d26a221c685a789379ef63cb2d082cedf3c2235",
	"2.0-beta7":  "473f15c04122dad810c919b2f3484d46560fd2dd4573f6695d387195816b02a6",
	"2.11.0":     "c32029b32da3d8cf2feca0790a4bc2331ea7eb62ab368a8980b90c7d8c8101e0",
	"2.0-rc2":    "ec411a34fee49692f196e4dc0a905b25d0667825904862fdba153df5e53183e0",
	"2.13.3":     "9529c55814264ab96b0eeba2920ac0805170969c994cc479bd3d4d7eb24a35a8",
	"2.0.2":      "c584d1000591efa391386264e0d43ec35f4dbb146cad9390f73358d9c84ee78d",
	"2.8.1":      "815a73e20e90a413662eefe8594414684df3d5723edcd76070e1a5aee864616e",
	"2.4":        "535e19bf14d8c76ec00a7e8490287ca2e2597cae2de5b8f1f65eb81ef1c2a4c6",
	"2.3":        "6ae3b0cb657e051f97835a6432c2b0f50a651b36b6d4af395bbe9060bb4ef4b2",
	"2.13.2":     "268dc17d3739992d4d1ca2c27f94630fb203a40d07e9ad5dfae131d4e3fa9764",
	"2.6.1":      "28433734bd9e3121e0a0b78238d5131837b9dbe26f1a930bc872bad44e68e44e",
	"2.11.1":     "a20c34cdac4978b76efcc9d0db66e95600bd807c6a0bd3f5793bcb45d07162ec",
	"2.2":        "c830cde8f929c35dad42cbdb6b28447df69ceffe99937bf420d32424df4d076a",
	"2.5":        "4f53e4d52efcccdc446017426c15001bb0fe444c7a6cdc9966f8741cf210d997",
	"2.15.0":     "419a8512895971b7b4f4f33e620d361254e5c9552b904b0474b09ddd4a6a220b",
	"2.16.0":     "5d241620b10e3f1475320bc9552cf7bcfa27eeb9b1b6a891449e76db4b4a02a8",
}

type unbufferedReaderAt struct {
	R io.ReadSeekCloser

	N int64
}

func NewUnbufferedReaderAt(r io.ReadSeekCloser) io.ReaderAt {
	return &unbufferedReaderAt{R: r}
}

func (u *unbufferedReaderAt) ReadAt(p []byte, off int64) (n int, err error) {

	if _, err := u.R.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}

	return u.R.Read(p)
}

func (b *fuzzer) IsAllowList(h []byte) bool {
	for _, v := range b.allowList {
		if bytes.Compare(v, h) == 0 {
			return true

		}
	}

	return false
}

type ArchiveFile interface {
	FileInfo() os.FileInfo
	Name() string
	Open() (io.ReadSeekCloser, error)
}

type ArchiveReader interface {
	Walk() <-chan interface{} // ArchiveFile or ArchiveError
}

type TARArchiveReader struct {
	*tar.Reader
}

type TARArchiveFile struct {
	*tar.Header

	r io.ReadSeeker
}

func (za *TARArchiveFile) Name() string {
	return za.Header.Name
}

type TARArchiveFileReader struct {
	io.ReadSeekCloser
}

// NopCloser returns a ReadCloser with a no-op Close method wrapping
// the provided Reader r.
func NopSeekCloser(r io.ReadSeeker) io.ReadSeekCloser {
	return nopSeekCloser{r}
}

type nopSeekCloser struct {
	io.ReadSeeker
}

func (nopSeekCloser) Close() error { return nil }

func (za *TARArchiveFile) Open() (io.ReadSeekCloser, error) {
	return &TARArchiveFileReader{NopSeekCloser(za.r)}, nil
}

func (za *TARArchiveFileReader) Close() error {
	io.Copy(io.Discard, za.ReadSeekCloser)
	return nil
}

func (za *TARArchiveReader) Walk() <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		for {
			header, err := za.Reader.Next()

			if err == io.EOF {
				break
			}

			if errors.Is(err, tar.ErrHeader) {
				// not a tar
				break
			}

			if errors.Is(err, io.ErrUnexpectedEOF) {
				// not a valid tar
				break
			}

			if err != nil {
				ch <- ArchiveError{p: "", Err: err}
				break
			}

			if header.Typeflag != tar.TypeReg {
				continue
			}

			lr := io.LimitReader(za.Reader, header.Size)

			buff := bytes.NewBuffer([]byte{})

			if _, err := io.Copy(buff, lr); err != nil {
				ch <- ArchiveError{p: "", Err: err}
				continue
			}

			ch <- &TARArchiveFile{header, bytes.NewReader(buff.Bytes())}
		}
	}()

	return ch
}

func NewGzipTARArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	gr, err := gzip.NewReader(io.NewSectionReader(br, 0, size))
	if err != nil {
		return nil, err
	}

	r2 := tar.NewReader(gr)

	return &TARArchiveReader{r2}, nil
}

func NewTARArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	r2 := tar.NewReader(io.NewSectionReader(br, 0, size))

	return &TARArchiveReader{r2}, nil
}

type DirectoryReader struct {
	p string
}

type DirectoryFile struct {
	fi os.FileInfo
	p  string
}

func (za *DirectoryFile) Name() string {
	return za.p
}
func (za *DirectoryFile) FileInfo() os.FileInfo {
	return za.fi
}

func (za *DirectoryFile) Open() (io.ReadSeekCloser, error) {
	r, err := os.OpenFile(za.p, os.O_RDONLY, 0)
	return r, err
}

type ArchiveError struct {
	p string

	Err error
}

func (ae *ArchiveError) Error() string {
	return ae.Err.Error()
}

func (za *DirectoryReader) Walk() <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		err := filepath.Walk(za.p, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				ch <- ArchiveError{p: za.p, Err: err}
				return nil
			}

			if !info.Mode().IsRegular() {
				return nil
			}

			ch <- &DirectoryFile{fi: info, p: path}
			return nil
		})

		if err != nil {
			ch <- ArchiveError{p: za.p, Err: err}
			return
		}
	}()

	return ch
}

func NewDirectoryReader(p string) (ArchiveReader, error) {
	return &DirectoryReader{p}, nil
}

type ZIPArchiveFile struct {
	*zip.File
}

func (za *ZIPArchiveFile) Name() string {
	return za.File.Name
}

func (za *ZIPArchiveFile) Open() (io.ReadSeekCloser, error) {
	r, err := za.File.Open()
	if err != nil {
		return nil, err
	}

	buff := bytes.NewBuffer([]byte{})

	if _, err := io.Copy(buff, r); err != nil {
		return nil, err
	}

	return NopSeekCloser(bytes.NewReader(buff.Bytes())), nil
}

type ZIPArchiveReader struct {
	*zip.Reader
}

func (za *ZIPArchiveReader) Walk() <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		defer close(ch)
		for _, f := range za.Reader.File {
			if f.FileHeader.Flags&0x1 == 1 {
				ch <- ArchiveError{
					p:   f.Name,
					Err: fmt.Errorf("Could not open encrypted file in zip: %s", f.Name),
				}

				continue
			}

			ch <- &ZIPArchiveFile{f}
		}
	}()

	return ch
}

func NewZipArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	r2, err := zip.NewReader(br, size)
	if err != nil {
		return nil, err
	}

	return &ZIPArchiveReader{r2}, nil
}

type Stats struct {
	files               uint64
	patched             uint64
	errors              uint64
	vulnerableLibraries uint64
	vulnerableFiles     uint64
}

func (s *Stats) Patched() uint64 {
	return atomic.LoadUint64(&s.patched)
}

func (s *Stats) Files() uint64 {
	return atomic.LoadUint64(&s.files)
}

func (s *Stats) IncPatched() {
	atomic.AddUint64(&s.patched, 1)
}

func (s *Stats) IncFile() {
	atomic.AddUint64(&s.files, 1)
}

func (s *Stats) Errors() uint64 {
	return atomic.LoadUint64(&s.errors)
}

func (s *Stats) IncError() {
	atomic.AddUint64(&s.errors, 1)
}

func (s *Stats) VulnerableFiles() uint64 {
	return atomic.LoadUint64(&s.vulnerableFiles)
}

func (s *Stats) IncVulnerableFile() {
	atomic.AddUint64(&s.vulnerableFiles, 1)
}

func (s *Stats) VulnerableLibraries() uint64 {
	return atomic.LoadUint64(&s.vulnerableLibraries)
}

func (s *Stats) IncVulnerableLibrary() {
	atomic.AddUint64(&s.vulnerableLibraries, 1)
}

type ArchiveWriter interface {
	Create(fh interface{}) (io.WriteCloser, error)
	Close() error
}

type DirectoryWriter struct {
}

func (za *DirectoryWriter) Create(fh interface{}) (io.WriteCloser, error) {
	zfh, ok := fh.(string)
	if !ok {
		return nil, fmt.Errorf("Expected path string")
	}

	fmt.Println("FIX PERMISSONS")
	// TODO(REMCO): fix permissions
	return os.OpenFile(zfh, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0770)
}

func (za *DirectoryWriter) Close() error {
	return nil
}

func NewDirectoryWriter(p string) (ArchiveWriter, error) {
	return &DirectoryWriter{}, nil
}

type ZIPArchiveWriter struct {
	*zip.Writer
}

type ZIPArchiveWriteCloser struct {
	io.Writer
}

func (wc *ZIPArchiveWriteCloser) Close() error {
	return nil
}

type TARArchiveWriter struct {
	*tar.Writer
}

func (za *TARArchiveWriter) Create(fh interface{}) (io.WriteCloser, error) {
	// should we use openraw
	tfh, ok := fh.(tar.Header)
	if !ok {
		return nil, fmt.Errorf("Expected tar fileheader")
	}

	if err := za.Writer.WriteHeader(&tfh); err != nil {
		return nil, err
	}

	return &TARArchiveWriteCloser{za.Writer}, nil
}

type TARArchiveWriteCloser struct {
	io.Writer
}

func (wc *TARArchiveWriteCloser) Close() error {
	return nil
}

func (za *ZIPArchiveWriter) Create(fh interface{}) (io.WriteCloser, error) {
	// should we use openraw

	zfh, ok := fh.(zip.FileHeader)
	if !ok {
		return nil, fmt.Errorf("Expected zip fileheader")
	}

	w, err := za.Writer.CreateHeader(&zfh)
	if err != nil {
		return nil, err
	}

	return &ZIPArchiveWriteCloser{w}, nil
}

func NewTARArchiveWriter(br io.Writer) (ArchiveWriter, error) {
	zw := tar.NewWriter(br)
	return &TARArchiveWriter{zw}, nil
}

func NewZipArchiveWriter(br io.Writer) (ArchiveWriter, error) {
	zw := zip.NewWriter(br)
	return &ZIPArchiveWriter{zw}, nil
}

func IsTAR(r io.ReadSeeker) (bool, error) {
	// get current pos
	c, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}

	block := [512]byte{}

	if _, err := r.Read(block[:]); err != nil {
		return false, err
	}

	// restore position
	_, err = r.Seek(c, io.SeekStart)
	return bytes.Compare(block[257:257+6], []byte("ustar\x00")) == 0, err
}

func (b *fuzzer) RecursivePatch(w []string, h []byte, r ArchiveReader, aw ArchiveWriter) (bool, error) {
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

					patched, err := b.RecursivePatch(append(w, f.Name()), hash, r2, w2)
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

					patched, err := b.RecursivePatch(append(w, f.Name()), hash, r2, w2)
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

					patched, err := b.RecursivePatch(append(w, f.Name()), hash, r2, w2)
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

func (b *fuzzer) RecursiveFind(w []string, h []byte, r ArchiveReader) error {
	// should check for hashes if vulnerable or not
	for v := range r.Walk() {
		if ae, ok := v.(ArchiveError); ok {
			fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not traverse into %s \u001b[0K", strings.Join(w, " -> "), ae.Error()))
			b.stats.IncError()
			continue
		}

		// only counting actual files
		if _, ok := (r.(*DirectoryReader)); ok {
			b.stats.IncFile()
		}

		f := v.(ArchiveFile)

		if err := func() error {
			if b.debug {
				fmt.Fprintln(b.writer.Bypass(), color.WhiteString("[!][%s] scanning %s \u001b[0K", strings.Join(append(w, f.Name()), " -> "), f.Name()))
			}

			// ignore files > 1GB
			size := f.FileInfo().Size()
			if size > 1073741824 {
				// skipping large file
				return nil
			} else if size == 0 {
				// skipping empty file
				return nil
			} else if size < 4 {
				// skipping small file
				return nil
			}

			rc, err := f.Open()
			if err != nil {
				return err
			}

			defer rc.Close()

			// calculate hash
			shaHash := sha256.New()

			if _, err := io.Copy(shaHash, rc); err != nil {
				b.stats.IncError()
				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not calculate hash \u001b[0K", strings.Join(append(w, f.Name()), " -> ")))
				return err
			}

			hash := shaHash.Sum(nil)

			if version, ok := b.signatures[string(hash)]; !ok {
			} else if b.IsAllowList(hash) {
			} else {
				b.stats.IncVulnerableLibrary()

				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] found vulnerable log4j with hash %x (version: %s) \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash, version))
			}

			rc.Seek(0, io.SeekStart)

			data := []byte{0, 0, 0, 0}
			if _, err := rc.Read(data); err != nil {
				b.stats.IncError()
				fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not read magic from file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
				return err
			}

			rc.Seek(0, io.SeekStart)

			// check for PK signature
			if bytes.Compare(data[0:4], []byte{0x50, 0x4B, 0x03, 0x04}) == 0 {
				r2, err := NewZipArchiveReader(NewUnbufferedReaderAt(rc), size)
				if err != nil {
					b.stats.IncError()
					fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open zip file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
					return err
				}

				return b.RecursiveFind(append(w, f.Name()), hash, r2)
			} else if bytes.Compare(data[0:3], []byte{0x1F, 0x8B, 0x08}) == 0 {
				// tgz
				r2, err := NewGzipTARArchiveReader(NewUnbufferedReaderAt(rc), size)
				if err != nil {
					b.stats.IncError()
					fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open tar file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
					return err
				}

				return b.RecursiveFind(append(w, f.Name()), hash, r2)
			} else if found, _ := IsTAR(rc); found {
				// always test if file is a tar
				r2, err := NewTARArchiveReader(NewUnbufferedReaderAt(rc), size)
				if err != nil {
					b.stats.IncError()
					fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] could not open tar file %x \u001b[0K", strings.Join(append(w, f.Name()), " -> "), hash))
					return err
				}

				return b.RecursiveFind(append(w, f.Name()), hash, r2)
			} else {
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
						// TODO(REMCO) : improve message!
						fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][%s] found JndiLookup class file with hash %x (version: %s) \u001b[0K", strings.Join(append(w, f.Name()), " -> "), h, version))
					}
				}

				return nil
			}
		}(); err != nil {
			fmt.Fprintln(b.writer.Bypass(), color.RedString("[!][ ] Error while scanning: %s => %s \u001b[0K", strings.Join(w, "->"), err))
		}
	}

	return nil
}

func (b *fuzzer) Patch() error {
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

		dr, err := NewDirectoryReader(target)
		if err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not create directory reader %s: %s\u001b[0K\n", target, err))
			continue
		}

		dw, err := NewDirectoryWriter(target)
		if err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not create directory writer %s: %s\u001b[0K\n", target, err))
			continue
		}

		if patched, err := b.RecursivePatch([]string{}, []byte{}, dr, dw); err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[✗] Could not walk into %s: %s\u001b[0K\n", target, err))
		} else if patched {
			fmt.Fprintf(b.writer.Bypass(), color.GreenString("[✓] Successfully patched %s => %s\u001b[0K\n", target, fmt.Sprintf("%s.patch", target)))
			b.stats.IncPatched()
		}
	}

	i := b.stats.Patched()
	sub := time.Now().Sub(start)
	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Patch finished! %d files patched, %d vulnerable files found, %d vulnerable libraries found, %d errors occured,  in %02.fh%02.fm%02.fs, average rate is: %0.f files/min. \u001b[0K", i, b.stats.VulnerableFiles(), b.stats.VulnerableLibraries(), b.stats.Errors(), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds(), float64(i)/sub.Minutes()))
	return nil
}

func (b *fuzzer) Run() error {
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

			i := b.stats.Files()

			fmt.Fprintf(b.writer, color.GreenString("[ ] Checked %d files in %02.fh%02.fm%02.fs, average rate is: %0.f files/min. \u001b[0K\n", atomic.LoadUint64(&i), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds(), float64(i)/sub.Minutes()))
			time.Sleep(time.Millisecond * 100)
		}
	}()

	for _, target := range b.targetPaths {
		dr, err := NewDirectoryReader(target)
		if err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not walk into %s: %s\u001b[0K\n", target, err))
		}

		if err := b.RecursiveFind([]string{}, []byte{}, dr); err != nil {
			fmt.Fprintf(b.writer.Bypass(), color.RedString("[ ] Could not walk into %s: %s\u001b[0K\n", target, err))
		}
	}

	i := b.stats.Files()
	sub := time.Now().Sub(start)
	fmt.Fprintln(b.writer.Bypass(), color.YellowString("[🏎]: Scan finished! %d files scanned, %d vulnerable files found, %d vulnerable libraries found, %d errors occured,  in %02.fh%02.fm%02.fs, average rate is: %0.f files/min. \u001b[0K", i, b.stats.VulnerableFiles(), b.stats.VulnerableLibraries(), b.stats.Errors(), sub.Seconds()/3600, sub.Seconds()/60, sub.Seconds(), float64(i)/sub.Minutes()))
	return nil
}
