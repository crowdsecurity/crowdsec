
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

# Go should not be required to run functional tests
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

#Current versioning information from env
BUILD_VERSION?=$(shell git describe --tags)
BUILD_CODENAME="alphaga"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG?=$(shell git rev-parse HEAD)
DEFAULT_CONFIGDIR?=/etc/crowdsec
DEFAULT_DATADIR?=/var/lib/crowdsec/data
