package app

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"text/template"

	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
)

type OptionFn func(b *fuzzer) error

func Dry() (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.dry = true
		return nil
	}, nil
}

func Rate(v int) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.rate = v
		return nil
	}, nil
}

func Output(v string) (func(b *fuzzer) error, error) {
	w, err := NewWriter(v)
	if err != nil {
		return nil, err
	}

	return func(b *fuzzer) error {
		b.output = w
		return nil
	}, nil
}

func Method(v string) (func(b *fuzzer) error, error) {
	if strings.ToUpper(v) == "GET" {
	} else if strings.ToUpper(v) == "HEAD" {
	} else {
		return nil, fmt.Errorf("Invalid method (GET|HEAD)")
	}

	return func(b *fuzzer) error {
		b.method = strings.ToUpper(v)
		return nil
	}, nil
}

func MaxRedirects(v int) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.maxRedirects = v
		return nil
	}, nil
}

func NumThreads(v int) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.numThreads = v
		return nil
	}, nil
}

func Debug() (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.debug = true
		return nil
	}, nil
}

func Verbose() (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.verbose = true
		return nil
	}, nil
}

type Template struct {
	Method  string                      `yaml: "method"`
	Headers map[string][]TemplateHeader `yaml:"headers"`
	Params  map[string][]TemplateHeader `yaml:"params"`
	Body    *TemplateBody               `yaml: "body"`
}

type TemplateBody struct {
	*template.Template
}

func (bt *TemplateBody) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v interface{}

	if err := unmarshal(&v); err != nil {
		return err
	}

	s, ok := v.(string)
	if !ok {
		return nil
	}

	tmpl, err := template.New("").Funcs(fm).Parse(s)
	if err != nil {
		return err
	}

	*bt = TemplateBody{tmpl}

	return nil
}

type TemplateHeader struct {
	*template.Template
}

func (bt *TemplateHeader) UnmarshalYAML(unmarshal func(interface{}) error) error {
	v := ""

	if err := unmarshal(&v); err != nil {
		return err
	}

	tmpl, err := template.New("").Funcs(fm).Parse(v)
	if err != nil {
		return err
	}

	*bt = TemplateHeader{tmpl}

	return nil
}

type TemplateParam struct {
	*template.Template
}

func (bt *TemplateParam) UnmarshalYAML(unmarshal func(interface{}) error) error {
	v := ""

	if err := unmarshal(&v); err != nil {
		return err
	}

	tmpl, err := template.New("").Funcs(fm).Parse(v)
	if err != nil {
		return err
	}

	*bt = TemplateParam{tmpl}

	return nil
}

var fm = template.FuncMap{
	"md5": func(s string) string {
		hash := md5.New()
		io.WriteString(hash, s)
		return fmt.Sprintf("%x", hash.Sum(nil))
	},
}

func TemplateOption(s string) (func(b *fuzzer) error, error) {
	data, err := os.ReadFile(s)
	if err != nil {
		return nil, err
	}

	t := Template{}

	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}

	return func(b *fuzzer) error {
		b.template = t

		fmt.Fprintf(os.Stdout, "[ ] Using template file: %s\n", s)
		return nil
	}, nil
}

func Hosts(hosts []string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.hosts = append(b.hosts, hosts...)

		fmt.Fprintf(os.Stdout, "[ ] Using hosts: %s\n", strings.Join(hosts, ","))
		return nil
	}, nil
}

func AllowList(values []string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.allowList = values

		fmt.Fprintf(os.Stdout, "[ ] Using allow list: %s\n", strings.Join(b.allowList, ","))
		return nil
	}, nil
}

func Targets(targets []string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		for _, target := range targets {
			b.targetHosts = append(b.targetHosts, target)
		}

		fmt.Fprintf(os.Stdout, "[ ] Using targets: %s\n", strings.Join(targets, ","))
		return nil
	}, nil
}

func ProxyURL(s string) (func(b *fuzzer) error, error) {
	dialer := net.Dial

	var proxyURL *url.URL

	if s == "" {
	} else if u, err := url.Parse(s); err != nil {
		return nil, err
	} else if v, err := proxy.FromURL(u, proxy.Direct); err != nil {
		return nil, err
	} else {
		dialer = v.Dial

		proxyURL = u
	}

	return func(b *fuzzer) error {
		b.dialer = dialer
		//caching dialer!!

		b.proxyURL = proxyURL

		fmt.Fprintf(os.Stdout, "[ ] Using proxy: %s\n", proxyURL.String())
		return nil
	}, nil
}

func Hostnames(s string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.hosts = strings.Split(s, ",")
		return nil
	}, nil
}
func Suffix(s string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.suffixes = strings.Split(s, ",")
		return nil
	}, nil
}

func UserAgent(s string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		// rotate?
		b.userAgent = s
		return nil
	}, nil
}
