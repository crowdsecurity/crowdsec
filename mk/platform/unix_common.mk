
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

# Go should not be required to run functional tests
GOOS ?= $(shell go env GOOS)

# Current versioning information from env
BUILD_VERSION?=$(shell git describe --tags)
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
DEFAULT_CONFIGDIR?=/etc/crowdsec
DEFAULT_DATADIR?=/var/lib/crowdsec/data

PKG_CONFIG:=$(shell command -v pkg-config 2>/dev/null)

# See if we have libre2-dev installed for C++ optimizations.
# In fedora and other distros, we need to tell where to find re2.pc
RE2_CHECK := $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs re2 2>/dev/null)
