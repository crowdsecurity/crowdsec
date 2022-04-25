SHELL           := /bin/bash
ALL_SRC         := $(shell find . -name "*.go" | grep -v -e vendor)
GIT_REMOTE_NAME ?= origin
MASTER_BRANCH   ?= master
GO              ?= go
ifdef TF_BUILD
	CI := on
endif
GOLANGCI_LINT_VERSION := v1.31.0

all: test

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ $(GOLANGCI_LINT_VERSION)

.PHONY: deps
deps: .golangci-bin

.PHONY: fmt
fmt:
	@gofmt -e -s -l -w $(ALL_SRC)

.PHONY: lint-go
lint-go: .golangci-bin
	@GO111MODULE=on .golangci-bin/golangci-lint run --timeout=10m --skip-files="test_bin/set_covermode.go"

.PHONY: lint
lint: lint-go 

.PHONY: test-go
test-go:
ifdef CI
	@# Run unit tests with coverage.
	@GO111MODULE=on $(GO) test ./... -v -coverpkg=github.com/confluentinc/bincover  -coverprofile=coverage.out
else
	@GO111MODULE=on $(GO) test ./... -v
endif

.PHONY: test
test: lint test-go

.PHONY: clean
clean:
	@rm -rf .golangci-bin
