Recursively scan archive files for `org/apache/logging/log4j/core/lookup/JndiLookup.class`, version 2.15.0 is allowed.

# find all versions at
https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.15.0

# Usage
```
go run main.go -allow cc7d55ed69cc5fd34035b15c6edf79a0 ./
```


# BUILD
```sh
GOARCH=amd64 GOOS=linux go build -o ./.builds/divd-2021-00038--log4j-scanner-amd64-linux ./main.go
```
