
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

# Go should not be required to run functional tests
GOOS ?= $(shell go env GOOS)

# Current versioning information from env
# The $(or) is used to ignore an empty BUILD_VERSION when it's an envvar,
# like inside a docker build: docker build --build-arg BUILD_VERSION=1.2.3
# as opposed to a make parameter: make BUILD_VERSION=1.2.3
BUILD_VERSION:=$(or $(BUILD_VERSION),$(shell git describe --tags --dirty))

BUILD_TIMESTAMP=$(shell date +%F"_"%T)
DEFAULT_CONFIGDIR?=/etc/crowdsec
DEFAULT_DATADIR?=/var/lib/crowdsec/data

PKG_CONFIG:=$(shell command -v pkg-config 2>/dev/null)

# See if we have libre2-dev installed for C++ optimizations.
# In fedora and other distros, we need to tell where to find re2.pc
RE2_CHECK := $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs re2 2>/dev/null)
