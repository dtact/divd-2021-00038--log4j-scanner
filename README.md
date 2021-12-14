# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.16.0.

# Scanning

## Usage

### Windows
```bash
divd-2021-00038--log4j-scanner-windows-amd64.exe {target-path}
```
### Linux
```bash
divd-2021-00038--log4j-scanner-linux-[amd64|arm64] {target-path}
```
### OSX
```bash
divd-2021-00038--log4j-scanner-darwin-amd64 {target-path}
```

# Patching

We've added preleminary support for recursively patching files. This is very experimental, be careful with this feature. Currently patching only works with
the archive (jar / tar ) file. The patch will create a new .patch file that needs to replace the original. Make sure you'll create a backup of the original file before replacing it. After patching you can 
scan again to make sure you didn't miss any files. Currently plain .class files in folders won't be patched, they can be removed safe manually.

Patching will remove the JndiLookup.class file from the inner archives.

## Usage

### Windows
```bash
divd-2021-00038--log4j-scanner-windows-amd64.exe patch {target-path}
```
### Linux
```bash
divd-2021-00038--log4j-scanner-linux-[amd64|arm64] patch {target-path}
```
### OSX
```bash
divd-2021-00038--log4j-scanner-darwin-amd64 patch {target-path}
```


## Build from source

Requirements:
- [Go 1.16 or newer](https://golang.org/dl/)

### For development
```bash
$ git clone "https://github.com/dtact/divd-2021-00038--log4j-scanner.git"
$ go build -o ./.builds/divd-2021-00038--log4j-scanner ./main.go
```

# Copyright and license

Code and documentation copyright 2021 Remco Verhoef (DTACT).

Code released under the MIT license.
