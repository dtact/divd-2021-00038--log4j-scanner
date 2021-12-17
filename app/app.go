package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
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
	excludeList []string

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
	b.writer.Out = color.Output

	for k, v := range signatures {
		for _, s := range v {
			h, _ := hex.DecodeString(s)
			b.signatures[string(h)] = k
		}
	}

	for _, optionFunc := range options {
		if err := optionFunc(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

var signatures = map[string][]string{
	"2.0-alpha2": []string{"bf4f41403280c1b115650d470f9b260a5c9042c04d9bcc2a6ca504a66379b2d6"},
	"2.0-beta5":  []string{"7d86841489afd1097576a649094ae1efb79b3147cd162ba019861dfad4e9573b"},
	"2.0-beta2":  []string{"ed285ad5ac6a8cf13461d6c2874fdcd3bf67002844831f66e21c2d0adda43fa4"},
	"2.10.0":     []string{"22b58febab566eddd5d4863f09dad4d5cc57677b6d4be745e3c6ce547124a66d"},
	"2.9.1":      []string{"dc435b35b5923eb05afe30a24f04e9a0a5372da8e76f986efe8508b96101c4ff"},
	"2.14.1":     []string{"ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0"},
	"2.0-beta3":  []string{"dbf88c623cc2ad99d82fa4c575fb105e2083465a47b84d64e2e1a63e183c274e"},
	"2.0-beta4":  []string{"a38ddff1e797adb39a08876932bc2538d771ff7db23885fb883fec526aff4fc8"},
	"2.9.0":      []string{"fb086e42c232d560081d5d76b6b9e0979e5693e5de76734cad5e396dd77278fd"},
	"2.14.0":     []string{"f04ee9c0ac417471d9127b5880b96c3147249f20674a8dbb88e9949d855382a8"},
	"2.0.1":      []string{"a00a54e3fb8cb83fab38f8714f240ecc13ab9c492584aa571aec5fc71b48732d"},
	"2.8.2":      []string{"10ef331115cbbd18b5be3f3761e046523f9c95c103484082b18e67a7c36e570c"},
	"2.0":        []string{"85338f694c844c8b66d8a1b981bcf38627f95579209b2662182a009d849e1a4c"},
	"2.7":        []string{"5bb84e110d5f18cee47021a024d358227612dd6dac7b97fa781f85c6ad3ccee4"},
	"2.13.0":     []string{"82e91afe0c5628b32ae99dd6965878402c668773fbd49b45b2b8c06a426c5bbb"},
	"2.0-rc1":    []string{"db3906edad6009d1886ec1e2a198249b6d99820a3575f8ec80c6ce57f08d521a"},
	"2.6":        []string{"df00277045338ceaa6f70a7b8eee178710b3ba51eac28c1142ec802157492de6"},
	"2.1":        []string{"8bdb662843c1f4b120fb4c25a5636008085900cdf9947b1dadb9b672ea6134dc"},
	"2.8":        []string{"ccf02bb919e1a44b13b366ea1b203f98772650475f2a06e9fac4b3c957a7c3fa"},
	"2.6.2":      []string{"cf65f0d33640f2cd0a0b06dd86a5c6353938ccb25f4ffd14116b4884181e0392"},
	"2.13.1":     []string{"88ebd503b35a0debe18c2707db9de33a8c6d96491270b7f02dd086b8072426b2"},
	"2.4.1":      []string{"42de36e61d454afff5e50e6930961c85b55d681e23931efd248fd9b9b9297239"},
	"2.11.2":     []string{"d4748cd5d8d67f513de7634fa202740490d7e0ab546f4bf94e5c4d4a11e3edbc"},
	"2.0-alpha1": []string{"006fc6623fbb961084243cfc327c885f3c57f2eba8ee05fbc4e93e5358778c85"},
	"2.0-beta1":  []string{"58e9f72081efff9bdaabd82e3b3efe5b1b9f1666cefe28f429ad7176a6d770ae"},
	"2.12.0":     []string{"8818f82570d3f509cfb27c209b9a8df6f188857b7462951a61a137be09cf3463"},
	"2.0-beta6":  []string{"4bfb0d5022dc499908da4597f3e19f9f64d3cc98ce756a2249c72179d3d75c47"},
	"2.0-beta8":  []string{"b3fae4f84d4303cdbad4696554b4e8d2381ad3faf6e0c3c8d2ce60a4388caa02"},
	"2.0-beta9":  []string{"dcde6033b205433d6e9855c93740f798951fa3a3f252035a768d9f356fde806d"},
	"2.12.1":     []string{"885e31a14fc71cb4849e93564d26a221c685a789379ef63cb2d082cedf3c2235"},
	"2.0-beta7":  []string{"473f15c04122dad810c919b2f3484d46560fd2dd4573f6695d387195816b02a6"},
	"2.11.0":     []string{"c32029b32da3d8cf2feca0790a4bc2331ea7eb62ab368a8980b90c7d8c8101e0"},
	"2.0-rc2":    []string{"ec411a34fee49692f196e4dc0a905b25d0667825904862fdba153df5e53183e0"},
	"2.13.3":     []string{"9529c55814264ab96b0eeba2920ac0805170969c994cc479bd3d4d7eb24a35a8"},
	"2.0.2":      []string{"c584d1000591efa391386264e0d43ec35f4dbb146cad9390f73358d9c84ee78d"},
	"2.8.1":      []string{"815a73e20e90a413662eefe8594414684df3d5723edcd76070e1a5aee864616e"},
	"2.4":        []string{"535e19bf14d8c76ec00a7e8490287ca2e2597cae2de5b8f1f65eb81ef1c2a4c6"},
	"2.3":        []string{"6ae3b0cb657e051f97835a6432c2b0f50a651b36b6d4af395bbe9060bb4ef4b2"},
	"2.13.2":     []string{"268dc17d3739992d4d1ca2c27f94630fb203a40d07e9ad5dfae131d4e3fa9764"},
	"2.6.1":      []string{"28433734bd9e3121e0a0b78238d5131837b9dbe26f1a930bc872bad44e68e44e"},
	"2.11.1":     []string{"a20c34cdac4978b76efcc9d0db66e95600bd807c6a0bd3f5793bcb45d07162ec"},
	"2.2":        []string{"c830cde8f929c35dad42cbdb6b28447df69ceffe99937bf420d32424df4d076a"},
	"2.5":        []string{"4f53e4d52efcccdc446017426c15001bb0fe444c7a6cdc9966f8741cf210d997"},
	"2.15.0":     []string{"419a8512895971b7b4f4f33e620d361254e5c9552b904b0474b09ddd4a6a220b"},
	"2.12.2":     []string{"7860bcf8c57fb80a1ccf9f65e245f00dae2ca13db104decfddf6c4b49c6b4c45"},
	"2.16.0": []string{
		// https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.16.0
		"5d241620b10e3f1475320bc9552cf7bcfa27eeb9b1b6a891449e76db4b4a02a8",
		// https://www.apache.org/dyn/closer.lua/logging/log4j/2.16.0/apache-log4j-2.16.0-bin.zip
		"085e0b34e40533015ba6a73e85933472702654e471c32f276e76cffcf7b13869",
	},
}

var fileSignatures = []struct {
	Filename string
	Hash     string
	Version  string
}{
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.16.0"},
	{"JndiLookup.class", "fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29", "2.0"},
	{"JndiLookup.class", "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8", "2.0-beta9"},
	{"JndiLookup.class", "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8", "2.0-rc1"},
	{"JndiLookup.class", "a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2", "2.0-rc2"},
	{"JndiLookup.class", "964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e", "2.0.1"},
	{"JndiLookup.class", "9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c", "2.0.2"},
	{"JndiLookup.class", "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307", "2.1"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.10.0"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.11.0"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.11.1"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.11.2"},
	{"JndiLookup.class", "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279", "2.12.0"},
	{"JndiLookup.class", "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279", "2.12.1"},
	{"JndiLookup.class", "febbc7867784d0f06934fec59df55ee45f6b24c55b17fff71cc4fca80bf22ebb", "2.12.2"},
	{"JndiLookup.class", "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f", "2.13.0"},
	{"JndiLookup.class", "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f", "2.13.1"},
	{"JndiLookup.class", "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f", "2.13.2"},
	{"JndiLookup.class", "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f", "2.13.3"},
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.14.0"},
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.14.1"},
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.15.0"},
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.16.0"},
	{"JndiLookup.class", "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307", "2.2"},
	{"JndiLookup.class", "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307", "2.3"},
	{"JndiLookup.class", "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7", "2.4"},
	{"JndiLookup.class", "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7", "2.4.1"},
	{"JndiLookup.class", "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7", "2.5"},
	{"JndiLookup.class", "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45", "2.6"},
	{"JndiLookup.class", "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45", "2.6.1"},
	{"JndiLookup.class", "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45", "2.6.2"},
	{"JndiLookup.class", "cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae", "2.7"},
	{"JndiLookup.class", "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442", "2.8"},
	{"JndiLookup.class", "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442", "2.8.1"},
	{"JndiLookup.class", "d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15", "2.8.2"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.9.0"},
	{"JndiLookup.class", "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e", "2.9.1"},
	{"JndiLookup.class", "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f", "2.14.1"},
}

func findFileHashes(hash []byte) []string {
	versions := []string{}

	for _, fh := range fileSignatures {
		dh, err := hex.DecodeString(fh.Hash)
		if err != nil {
			panic(err)
		}

		if bytes.Compare(hash, dh) != 0 {
			continue
		}

		versions = append(versions, fh.Version)
	}

	return versions
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

			size := header.Size

			if size > 1073741824 {
				// bailing out when file in tar is too large
				ch <- ArchiveError{p: header.Name, Err: fmt.Errorf("Could not scan file, file too large: %d bytes.", header.Size)}
				break
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
	p           string
	excludeList []string
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

			// only exclude real fs files
			if info.IsDir() && IsExcluded(path, za.excludeList) {
				return filepath.SkipDir
			}

			if IsExcluded(path, za.excludeList) {
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

func NewDirectoryReader(p string, excludeList []string) (ArchiveReader, error) {
	return &DirectoryReader{p, excludeList}, nil
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
	images              uint64
	patched             uint64
	errors              uint64
	vulnerableLibraries uint64
	vulnerableFiles     uint64
}

func (s *Stats) Patched() uint64 {
	return atomic.LoadUint64(&s.patched)
}

func (s *Stats) Images() uint64 {
	return atomic.LoadUint64(&s.images)
}

func (s *Stats) IncImage() {
	atomic.AddUint64(&s.images, 1)
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
	panic("this code isn't being used")
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

func IsExcluded(p string, l []string) bool {
	for _, g := range l {
		// we've checked the patterns before
		if matched, _ := path.Match(g, p); matched {
			return matched
		}
	}

	return false
}

func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	return fmt.Sprintf("%02dh:%02dm:%02ds", h, m, s)
}
