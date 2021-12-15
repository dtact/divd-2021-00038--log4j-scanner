# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.16.0.

:bangbang: | This software still very alpha, stay cautious when using this applicatin. We've tested it in quite a few cases, and it *seems* to work correctly. If you have any doubts, requests or issues please create an issue.
:---: | :---

# Scanning

## Usage

### Windows
```bash
$ divd-2021-00038--log4j-scanner.exe {target-path}
```
### Linux / OSX / FreeBSD
```bash
$ divd-2021-00038--log4j-scanner {target-path}
```

### Docker containers

If you want to scan docker containers, you can do the following. Due to the recursive nature of the application, you can scan into all layers of archives. Lets try with the log4j vulnerable docker container: https://github.com/christophetd/log4shell-vulnerable-app.


```bash
$ docker save log4shell | gzip > ./log4shell-image.tar.gz
$ divd-2021-00038--log4j-scanner-darwin-amd64 ./log4shell-image.tar.gz
```

You can also patch the image:

```bash
$ docker save log4shell > ./log4shell-image.tar
$ divd-2021-00038--log4j-scanner-darwin-amd64 ./log4shell-image.tar
$ divd-2021-00038--log4j-scanner-darwin-amd64 patch ./log4shell-image.tar
$ cat ./log4shell-image.tar.patch | docker load 
```

Comparing both tars will give the following differences:

``` 
Binary files ../2/BOOT-INF/lib/log4j-core-2.14.1.jar and ./BOOT-INF/lib/log4j-core-2.14.1.jar differ
Binary files ../2/app/spring-boot-application.jar and ./app/spring-boot-application.jar differ
Binary files ../2/b0d66ac73d47865118cfb9a1244f1508d94ea938da1eb78c2db20bd2e1a6629a/layer.tar and ./b0d66ac73d47865118cfb9a1244f1508d94ea938da1eb78c2db20bd2e1a6629a/layer.tar differ
Only in ./org/apache/logging/log4j/core/lookup: JndiLookup.class
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
