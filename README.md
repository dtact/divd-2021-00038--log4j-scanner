# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.17.0 and 2.12.3.

![Scanning multi layered archives](./images/log4j-solr.gif)

# Features

* scans recursively through all archives in archives in archives in archives etc
* scan for known log4j libraries (sha256 hash)
* scan for JndiLookup.class files
* fast
* show related CVE's found by version
* detects class files with different extensions (eg .ezclass)
* scans through all layers of local- and remote docker images
* *binary* versions available for Windows, Linux and MacOS
* includes *patching*, which will delete (again recursively) the JndiLookup class


# References

| CVE | References | 
|-----|------------|
| CVE-2021-44228 | https://www.cve.org/CVERecord?id=CVE-2021-44228 |
| CVE-2021-45046 | https://www.cve.org/CVERecord?id=CVE-2021-45046 |
| CVE-2021-45105 | https://www.cve.org/CVERecord?id=CVE-2021-45105 |

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

Using the tool you can now also scan containers: 


```bash
$ ./divd-2021-00038--log4j-scanner scan-image logstash:7.16.1
```

or local images:

```bash
$ ./divd-2021-00038--log4j-scanner scan-image --local {sha256|pattern}
$ ./divd-2021-00038--log4j-scanner scan-image --local log4shell:latest
$ ./divd-2021-00038--log4j-scanner scan-image --local 4949add9e671

# scan all local images
$ ./divd-2021-00038--log4j-scanner scan-image --local 

```


You can also patch the image:

```bash
$ docker save log4shell > ./log4shell-image.tar
$ ./divd-2021-00038--log4j-scanner ./log4shell-image.tar
$ ./divd-2021-00038--log4j-scanner patch ./log4shell-image.tar
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
$ divd-2021-00038--log4j-scanner.exe patch {target-path}
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
