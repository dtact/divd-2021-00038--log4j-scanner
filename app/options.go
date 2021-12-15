package app

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
)

type OptionFn func(b *fuzzer) error

func Dry() (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		b.dry = true
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

func ExcludeList(values []string) (func(b *fuzzer) error, error) {
	globs := make([]string, len(values))

	for i, value := range values {
		// check for bad syntaxes
		_, err := path.Match("test", value)
		if err != nil {
			return nil, err
		}

		globs[i] = value
	}

	return func(b *fuzzer) error {

		b.excludeList = globs

		fmt.Fprintf(os.Stdout, "[ ] Using exclude list: %s\n", strings.Join(b.excludeList, ", "))
		return nil
	}, nil
}

func AllowList(values []string) (func(b *fuzzer) error, error) {
	bvalues := make([][]byte, len(values))

	for i, _ := range values {
		v, err := hex.DecodeString(values[i])
		if err != nil {
			return nil, err
		}

		bvalues[i] = v
	}

	return func(b *fuzzer) error {
		b.allowList = bvalues

		return nil
	}, nil
}

func Remotes(remote []string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		for _, rh := range remote {
			b.remoteHosts = append(b.remoteHosts, rh)
		}

		fmt.Fprintf(os.Stdout, "[ ] Using remote hosts: %s\n", strings.Join(remote, ", "))
		return nil
	}, nil
}

func TargetPaths(targets []string) (func(b *fuzzer) error, error) {
	return func(b *fuzzer) error {
		for _, target := range targets {
			b.targetPaths = append(b.targetPaths, target)
		}

		fmt.Fprintf(os.Stdout, "[ ] Using targets: %s\n", strings.Join(targets, ","))
		return nil
	}, nil
}
