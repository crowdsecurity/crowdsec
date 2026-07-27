
RM=rm -rf
CP=cp
CPR=cp -r
MKDIR=mkdir -p

# Go should not be required to run functional tests
GOOS ?= $(shell go env GOOS)

# Current versioning information from env
#
# git describe returns the most recent tag that is an ANCESTOR of HEAD. Releases
# are tagged on dedicated branches (e.g. releases/1.7.x) that are never merged
# back, so on master/dev branches describe stays stuck at the branch-off tag
# (e.g. v1.7.5) and pins dev builds to a stale hub branch. When the describe
# output carries a "-<N>-g<sha>" suffix (i.e. HEAD is not on a release tag) we
# report the latest release tag with a -dev marker instead, so BaseVersion()
# matches the newest release and the hub resolves to 'master'. On an exact tag
# (release build) the describe output is used verbatim.
#
# The $(or) is used to ignore an empty BUILD_VERSION when it's an envvar,
# like inside a docker build: docker build --build-arg BUILD_VERSION=1.2.3
# as opposed to a make parameter: make BUILD_VERSION=1.2.3
BUILD_VERSION := $(or $(BUILD_VERSION),$(shell \
	descr=$$(git describe --tags --dirty); \
	if echo "$$descr" | grep -qE -- '-[0-9]+-g[0-9a-f]+'; then \
		latest=$$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
		dirty=$$(echo "$$descr" | grep -oE -- '-dirty$$'); \
		echo "$${latest}-dev-g$$(git rev-parse --short HEAD)$${dirty}"; \
	else \
		echo "$$descr"; \
	fi))

BUILD_TIMESTAMP=$(shell date +%F"_"%T)
DEFAULT_CONFIGDIR?=/etc/crowdsec
DEFAULT_DATADIR?=/var/lib/crowdsec/data

PKG_CONFIG:=$(shell command -v pkg-config 2>/dev/null)

# See if we have libre2-dev installed for C++ optimizations.
# In fedora and other distros, we need to tell where to find re2.pc
RE2_CHECK := $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs re2 2>/dev/null)
