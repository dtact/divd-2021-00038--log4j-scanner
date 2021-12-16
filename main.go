package main

import (
	"github.com/dutchcoders/divd-2021-00038--log4j-scanner/cmd"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func main() {
	cli.ErrWriter = color.Output

	app := cmd.New()
	app.RunAndExitOnError()
}
