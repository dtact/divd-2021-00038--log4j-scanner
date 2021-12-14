package cmd

import (
	"fmt"
	"strings"

	dirbuster "github.com/dutchcoders/divd-2021-00038--log4j-scanner/app"
	build "github.com/dutchcoders/divd-2021-00038--log4j-scanner/build"
	"github.com/fatih/color"
	logging "github.com/op/go-logging"

	cli "github.com/urfave/cli/v2"
)

var Version = fmt.Sprintf("%s (build on %s)", build.ShortCommitID, build.BuildDate)

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
	&cli.StringFlag{
		Name:  "targets",
		Usage: "",
		Value: "",
	},
	&cli.StringSliceFlag{
		Name:  "allow",
		Usage: "the allow files",
		Value: cli.NewStringSlice(
			"5d241620b10e3f1475320bc9552cf7bcfa27eeb9b1b6a891449e76db4b4a02a8"),
	},
	&cli.IntFlag{
		Name:  "num-threads",
		Usage: "the number of threads to use",
		Value: 10,
	},
	&cli.BoolFlag{
		Name:  "dry",
		Usage: "enable dry run mode",
	},
	&cli.BoolFlag{
		Name:  "verbose",
		Usage: "enable verbose mode",
	},
	&cli.BoolFlag{
		Name:  "debug",
		Usage: "enable debug mode",
	},
	&cli.BoolFlag{
		Name:  "json",
		Usage: "output json",
	},
}

type Cmd struct {
	*cli.App
}

func VersionAction(c *cli.Context) error {
	fmt.Println(color.YellowString(fmt.Sprintf("dirbuster")))
	return nil
}

func New() *Cmd {
	app := cli.NewApp()
	app.Name = "divd-2021-00038--log4j-scanner"
	app.Usage = ""
	app.Description = ``
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []*cli.Command{
		{
			Name:   "version",
			Action: VersionAction,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) error {
		fmt.Println("divd-2021-00038--log4j-scanner by DTACT")
		fmt.Println("http://github.com/dtact/divd-2021-00038--log4j-scanner")
		fmt.Println("--------------------------------------")

		options := []dirbuster.OptionFn{}

		v := c.Int("num-threads")
		if fn, err := dirbuster.NumThreads(v); err != nil {
			ec := cli.NewExitError(color.RedString(err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		if targets := c.String("targets"); targets == "" {
		} else if fn, err := dirbuster.TargetPaths(strings.Split(targets, ",")); err != nil {
			ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
			return ec
		} else {
			options = append(options, fn)
		}

		if allowList := c.StringSlice("allow"); len(allowList) == 0 {
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

		if args := c.Args(); !args.Present() {
		} else if fn, err := dirbuster.TargetPaths(args.Slice()); err != nil { //|| fn.Host == "" {
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
