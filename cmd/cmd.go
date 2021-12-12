package cmd

import (
	"fmt"
	"strings"

	dirbuster "github.com/dutchcoders/divd-2021-00038--log4j-scanner/app"
	"github.com/fatih/color"
	logging "github.com/op/go-logging"

	cli "github.com/urfave/cli"
)

var Version = "0.1"
var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
{{end}}{{if .Flags}}
FLAGS:
{{range .Flags}}{{.}}
{{end}}{{end}}
VERSION:
` + Version +
	`{{ "\n"}}`

var log = logging.MustGetLogger("dirbuster/cmd")

var globalFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "targets",
		Usage: "",
		Value: "",
	},
	cli.StringSliceFlag{
		Name:  "allow",
		Usage: "the allow files",
		Value: func() *cli.StringSlice {
			s := cli.StringSlice([]string{
				"81e0433ae00602c0e4d00424d213b0ab"})
			return &s
		}(),
	},
	cli.IntFlag{
		Name:  "num-threads",
		Usage: "the number of threads to use",
		Value: 10,
	},
	cli.BoolFlag{
		Name:  "dry",
		Usage: "enable dry run mode",
	},
	cli.IntFlag{
		Name:  "max-redirects",
		Usage: "max number of redirects",
		Value: 0,
	},
	cli.BoolFlag{
		Name:  "verbose",
		Usage: "enable verbose mode",
	},
	cli.BoolFlag{
		Name:  "debug",
		Usage: "enable debug mode",
	},
	cli.BoolFlag{
		Name:  "json",
		Usage: "output json",
	},
}

type Cmd struct {
	*cli.App
}

func VersionAction(c *cli.Context) {
	fmt.Println(color.YellowString(fmt.Sprintf("dirbuster")))
}

func New() *Cmd {
	app := cli.NewApp()
	app.Name = "divd-2021-00038--log4j-scanner"
	app.Author = "DTACT (https://dtact.com/)"
	app.Usage = ""
	app.Description = ``
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []cli.Command{
		{
			Name:   "version",
			Action: VersionAction,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) error {
		fmt.Println("divd-2021-00038--log4j-scanner")
		fmt.Println("http://github.com/dtact/divd-2021-00038--log4j-scanner")
		fmt.Println("--------------------------------------")

		options := []dirbuster.OptionFn{}

		v := c.GlobalInt("num-threads")
		if fn, err := dirbuster.NumThreads(v); err != nil {
			ec := cli.NewExitError(color.RedString(err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		if targets := c.GlobalString("targets"); targets == "" {
		} else if fn, err := dirbuster.Targets(strings.Split(targets, ",")); err != nil {
			ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		if allowList := c.GlobalStringSlice("allow"); len(allowList) == 0 {
		} else if fn, err := dirbuster.AllowList(allowList); err != nil {
			ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		if !c.Bool("dry") {
		} else if fn, err := dirbuster.Dry(); err != nil {
		} else {
			options = append(options, fn)
		}

		if !c.Bool("debug") {
		} else if fn, err := dirbuster.Debug(); err != nil {
		} else {
			options = append(options, fn)
		}

		if !c.Bool("verbose") {
		} else if fn, err := dirbuster.Verbose(); err != nil {
		} else {
			options = append(options, fn)
		}

		if args := c.Args(); len(args) == 0 {
		} else if fn, err := dirbuster.Targets(args); err != nil { //|| fn.Host == "" {
			ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		b, err := dirbuster.New(options...)
		if err != nil {
			ec := cli.NewExitError(color.RedString("[!] Error: %s", err.Error()), 1)
			return ec
		}

		if err := b.Run(); err != nil {
			ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
			return ec
		}

		return nil
	}
	return &Cmd{
		App: app,
	}
}
