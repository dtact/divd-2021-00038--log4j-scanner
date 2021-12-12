# divd-2021-00038--log4j-scanner

This scanner will recursively scan paths including archives for vulnerable log4j versions and `org/apache/logging/log4j/core/lookup/JndiLookup.class` files. 

Currently the allow list defines non exploitable versions, in this case log4j-core 2.15.0.

# Usage (windows)
```
divd-2021-00038--log4j-scanner-windows-amd64.exe {target-path}
```
# Usage (linux)
```
divd-2021-00038--log4j-scanner-linux-[amd64|arm64] {target-path}
```
# Usage (mac)
```
divd-2021-00038--log4j-scanner-darwin-amd64 {target-path}
```


# BUILD
```sh
GOARCH=amd64 GOOS=linux go build -o ./.builds/divd-2021-00038--log4j-scanner-linux-amd64 ./main.go
```

# Copyright and license

Code and documentation copyright 2011-2020 Remco Verhoef (DTACT).

Code released under the MIT license.
