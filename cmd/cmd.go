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
		Usage: "the non-vulnerable library (log4j 2.12.3 and 2.17) hashes ",
		Value: cli.NewStringSlice(
			// 2.3.1
			"d3057c7d413af1bf8f71ef9a2e6aa01896157ea13ed0819e4296b042b6d08fdf",
			// 2.12.3
			"41058a16e1fa17ae6f2d9d4f8ed20b3e39443b7fcb97d3b057a697087ae53907",
			// 2.17.1
			"7e9ee383f6c730557c133bb7a840b7a4225c14e786d543aeae079b3173b58017",
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

		color.NoColor = c.Bool("disable-color")
		return nil
	}

	app.Action = ScanAction
	return &Cmd{
		App: app,
	}
}
