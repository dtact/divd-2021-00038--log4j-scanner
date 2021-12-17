package cmd

import (
	"fmt"

	dirbuster "github.com/dutchcoders/divd-2021-00038--log4j-scanner/app"
	build "github.com/dutchcoders/divd-2021-00038--log4j-scanner/build"
	"github.com/fatih/color"
	logging "github.com/op/go-logging"

	cli "github.com/urfave/cli/v2"
)

var log = logging.MustGetLogger("dirbuster/cmd")

var globalFlags = []cli.Flag{
	&cli.StringSliceFlag{
		Name:  "targets",
		Usage: "",
		Value: cli.NewStringSlice(),
	},
	&cli.StringSliceFlag{
		Name:  "exclude",
		Usage: "exclude the following file paths (glob)",
		Value: cli.NewStringSlice(),
	},
	&cli.StringSliceFlag{
		Name:  "allow",
		Usage: "the allowed library (log4j 2.16) hashes ",
		Value: cli.NewStringSlice(
			// https://www.apache.org/dyn/closer.lua/logging/log4j/2.12.2/apache-log4j-2.12.2-bin.tar.gz
			"7860bcf8c57fb80a1ccf9f65e245f00dae2ca13db104decfddf6c4b49c6b4c45",
			// https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.16.0
			"5d241620b10e3f1475320bc9552cf7bcfa27eeb9b1b6a891449e76db4b4a02a8",
			// https://www.apache.org/dyn/closer.lua/logging/log4j/2.16.0/apache-log4j-2.16.0-bin.zip
			"085e0b34e40533015ba6a73e85933472702654e471c32f276e76cffcf7b13869",
		),
	},
	&cli.BoolFlag{
		Name:  "disable-color",
		Usage: "disable color output",
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

func ScanImageAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
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

	if allowList := c.StringSlice("allow"); len(allowList) == 0 {
	} else if fn, err := dirbuster.AllowList(allowList); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
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

	if err := b.ScanImage(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}

func PatchAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
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

	if allowList := c.StringSlice("allow"); len(allowList) == 0 {
	} else if fn, err := dirbuster.AllowList(allowList); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
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

	if err := b.Patch(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}

func ScanAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	v := c.Int("num-threads")
	if fn, err := dirbuster.NumThreads(v); err != nil {
		ec := cli.NewExitError(color.RedString(err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if exclude := c.StringSlice("exclude"); len(exclude) == 0 {
	} else if fn, err := dirbuster.ExcludeList(exclude); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set exclude list: %s", err.Error()), 1)
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

	if err := b.Scan(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}
func New() *Cmd {
	app := cli.NewApp()
	app.Name = "divd-2021-00038--log4j-scanner"
	app.Copyright = "All rights reserved Remco Verhoef [DTACT]"
	app.Authors = []*cli.Author{
		{
			Name:  "Remco Verhoef",
			Email: "remco.verhoef@dtact.com",
		}}
	app.Description = `This application will scan recursively through archives to detect log4j libraries and the JndiLookup class files.`
	app.Flags = globalFlags
	app.Commands = []*cli.Command{
		{
			Name:   "scan",
			Action: ScanAction,
		},
		{
			Name:   "patch",
			Action: PatchAction,
		},
		{
			Name:   "scan-image",
			Action: ScanImageAction,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "local",
					Usage: "scan local images",
				},
			},
		},
	}

	app.Version = fmt.Sprintf("%s (build on %s)", build.ReleaseTag, build.BuildDate)
	app.Before = func(c *cli.Context) error {
		fmt.Println("divd-2021-00038--log4j-scanner by DTACT")
		fmt.Println("http://github.com/dtact/divd-2021-00038--log4j-scanner")
		fmt.Println("--------------------------------------")

		color.NoColor = c.Bool("no-color")
		return nil
	}

	app.Action = ScanAction
	return &Cmd{
		App: app,
	}
}
