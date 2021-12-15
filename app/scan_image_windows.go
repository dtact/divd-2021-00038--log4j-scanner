package app

import (
	"fmt"

	cli "github.com/urfave/cli/v2"

	"github.com/fatih/color"
	_ "github.com/op/go-logging"
)

func (b *fuzzer) ScanImage(ctx *cli.Context) error {
	fmt.Fprintf(b.writer, color.RedString("Scanning docker images is not supported on Windows"))
	return nil
}
