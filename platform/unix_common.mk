
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

GO_MAJOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)

BUILD_GOVERSION="$(shell go version | cut -d " " -f3 | sed -E 's/[go]+//g')"

#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags $$(git rev-list --tags --max-count=1))"
BUILD_CODENAME=$(shell cat RELEASE.json | jq -r .CodeName)
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG?="$(shell git rev-parse HEAD)"