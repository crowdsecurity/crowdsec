include Makefile.help.mk

BINARY=namegenerator
MAIN_PACKAGE=cmd/${BINARY}/main.go
PACKAGES = $(shell go list ./...)
VERSION=`cat VERSION`
BUILD=`git symbolic-ref HEAD 2> /dev/null | cut -b 12-`-`git log --pretty=format:%h -1`
DIST_FOLDER=dist
DIST_INCLUDE_FILES=README.md LICENSE VERSION

# Setup -ldflags option for go build here, interpolate the variable values
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

# Build & Install

install:		## Build and install package on your system
	go install $(LDFLAGS) -v $(PACKAGES)

.PHONY: version
version:		## Show version information
	@echo $(VERSION)-$(BUILD)

# Testing

.PHONY: test
test:			## Execute package tests 
	go test -v $(PACKAGES)

.PHONY: test-race
test-race:
	go test -race -v $(PACKAGES)

.PHONY: cover-profile
cover-profile:
	echo "mode: count" > coverage-all.out
	$(foreach pkg,$(PACKAGES),\
		go test -coverprofile=coverage.out -covermode=count $(pkg);\
		tail -n +2 coverage.out >> coverage-all.out;)
	rm -rf coverage.out

.PHONY: cover
cover: cover-profile	
cover: 			## Generate test coverage data
	go tool cover -func=coverage-all.out

.PHONY: cover-html
cover-html: cover-profile
cover-html:		## Generate coverage report
	go tool cover -html=coverage-all.out

.PHONY: codecov
codecov:
	bash <(curl -s https://codecov.io/bash)

# BenchMarking

.PHONY: benchmark
benchmark:		## Execute package benchmarks 
	go test -v $(PACKAGES) -benchmem -bench . 

# Dependencies

deps:			## Install build dependencies
	go get -u=patch
	go mod tidy -v
	go mod download
	go mod verify

dev-deps: deps
dev-deps:		## Install dev and build dependencies

.PHONY: clean
clean:			## Delete generated development environment
	go clean
	rm -rf ${BINARY}-*-*
	rm -rf ${BINARY}-*-*.exe
	rm -rf ${BINARY}-*-*.zip
	rm -rf coverage-all.out

# Lint

.PHONY: lint
lint:			## Lint source code
	./lint.bash

# Docs

godoc-serve:		## Serve documentation (godoc format) for this package at port HTTP 9090
	godoc -http=":9090"
