VERSION   = $(shell git describe --dirty --tags 2>/dev/null)
GOVERSION = $(shell go version|awk '{ print $$3 }')
DATE      = $(shell date +%F-%T-%Z)
NPROC     = $(if ${NPROC},${NPROC},$(shell nproc))
COMMIT_ID = $(shell git log --format=%H -n1)
SHORT_COMMIT_ID = $(shell git log --format=%H -n1|cut -c1-12)
ROOTDIR   = $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
GO        = go
GOARGS   =
PROFILE_OPTS = tool pprof -nodefraction=0 -http :5000
DATE=$(shell date +'%Y%m%d%H%M%S')
CUR_DIR = $(shell pwd)

WORKDIR   = ${ROOTDIR}/.build

MODULE 	  = go.dutchsec.com/divd-2021-00038--log4j-scanner
TESTS = .*

define LDFLAGS
-X '$(MODULE)/build.BuildDate=$(DATE)' \
-X '$(MODULE)/build.CommitID=$(COMMIT_ID)' \
-X '$(MODULE)/build.ShortCommitID=$(SHORT_COMMIT_ID)' \
-X '$(MODULE)/build.GoVersion=$(GOVERSION)'
endef

ifneq ($(strip $(VERSION)),)
LDFLAGS+=-X '$(MODULE)/build.Version=$(VERSION)' \
		 -X '$(MODULE)/build.ReleaseTag=$(VERSION)'
endif

ifneq ($(strip $(CPU_PROFILE)),)
CPU_PROFILE_FILE=/tmp/cpu.$(DATE).out
GOARGS+=-cpuprofile $(CPU_PROFILE_FILE)
endif

ifneq ($(strip $(MEM_PROFILE)),)
MEM_PROFILE_FILE=/tmp/mem.$(DATE).out
GOARGS+=-memprofile $(MEM_PROFILE_FILE)
endif

ifneq ($(strip $(COVER_PROFILE)),)
COVERAGE_FILE=/tmp/cover.$(DATE).html
GOTESTARGS+=-coverprofile $(COVERAGE_FILE)
endif

CI_PROJECT_NAME=divd-2021-00038--log4j-scanner

test:
	$(GO) test ./...

build:
	mkdir -p .builds
	GOFLAGS="" GOARCH=amd64 GOOS=darwin $(GO) build -ldflags "$(LDFLAGS)" -o .builds/${CI_PROJECT_NAME}-darwin-amd64 .
	GOFLAGS="" GOARCH=amd64 GOOS=windows $(GO) build -ldflags "$(LDFLAGS)" -o .builds/${CI_PROJECT_NAME}-windows-amd64.exe .
	GOFLAGS="" GOARCH=amd64 GOOS=linux $(GO) build -ldflags "$(LDFLAGS)" -o .builds/${CI_PROJECT_NAME}-linux-amd64 .
	GOFLAGS="" GOARCH=arm64 GOOS=linux $(GO) build -ldflags "$(LDFLAGS)" -o .builds/${CI_PROJECT_NAME}-linux-arm64 .

lint:
	golangci-lint run . #/...

.PHONY: build run test
