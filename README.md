# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.16.0.

:bangbang: | This software still very alpha, stay cautious when using this applicatin. We've tested it in quite a few cases, and it seems to work correctly in many cases. If you have any doubts, requests or issues please create an issue.
:---: | :---

# Scanning

## Usage

### Windows
```bash
divd-2021-00038--log4j-scanner.exe {target-path}
```
### Linux / OSX / FreeBSD
```bash
divd-2021-00038--log4j-scanner {target-path}
```

# Patching

We've added preleminary support for recursively patching files. This is very experimental, be careful with this feature. Currently patching only works with
the archive (jar / tar ) file. The patch will create a new `.patch`` file that needs to replace the original file. This is on purpose a manual process, as it needs to be timed with restarting services. Make sure you'll create a backup of the original file before replacing it. After patching you can scan again to make sure you didn't miss any files. Currently plain .class files in folders won't be patched, as they can be removed safe manually.

The `.patch` file will be exactly the same as the original file, without `JndiLookup.class`. This should be sufficient to mitigate this issue, while waiting for upgrades. Make sure to make backups and test thoroughly.

Patch will refuse to run on folders, as a precaution. Just point patch to the vulnerable archive.

## Usage

### Windows
```bash
divd-2021-00038--log4j-scanner.exe patch {target-path}
```
### Linux / OSX / FreeBSD
```bash
divd-2021-00038--log4j-scanner patch {target-path}
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
