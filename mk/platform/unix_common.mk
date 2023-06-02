
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

# override with "make RE2_TAG=" to use the WebAssembly regexp library
# override with "make RE2_TAG=re2_cgo" to use the C++ regexp library
RE2_TAG ?= $(shell echo "int main() { return 0; }" | $(CC) -x c - -o /dev/null -lre2 >/dev/null 2>&1 && echo re2_cgo)
