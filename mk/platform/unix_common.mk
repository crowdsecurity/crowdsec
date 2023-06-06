
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

# Go should not be required to run functional tests
GOOS ?= $(shell go env GOOS)

#Current versioning information from env
BUILD_VERSION?=$(shell git describe --tags)
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
DEFAULT_CONFIGDIR?=/etc/crowdsec
DEFAULT_DATADIR?=/var/lib/crowdsec/data
