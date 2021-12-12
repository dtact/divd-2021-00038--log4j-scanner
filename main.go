package main

import "github.com/dutchcoders/divd-2021-00038--log4j-scanner/cmd"

func main() {
	app := cmd.New()
	app.RunAndExitOnError()
}
