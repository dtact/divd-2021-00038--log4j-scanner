# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.15.0.

# Usage
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


# Development
```sh
GOARCH=amd64 GOOS=linux go build -o ./.builds/divd-2021-00038--log4j-scanner-linux-amd64 ./main.go
```

# Copyright and license

Code and documentation copyright 2021 Remco Verhoef (DTACT).

Code released under the MIT license.
