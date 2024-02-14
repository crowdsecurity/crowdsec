include mk/platform.mk
include mk/gmsl

# By default, this build requires the C++ re2 library to be installed.
#
# Debian/Ubuntu: apt install libre2-dev
# Fedora/CentOS: dnf install re2-devel
# FreeBSD:       pkg install re2
# Alpine:        apk add re2-dev
# Windows:       choco install re2
# MacOS:         brew install re2

# To build without re2, run "make BUILD_RE2_WASM=1"
# The WASM version is slower and introduces a short delay when starting a process
# (including cscli) so it is not recommended for production use.
BUILD_RE2_WASM ?= 0

# To build static binaries, run "make BUILD_STATIC=1".
# On some platforms, this requires additional packages
# (e.g. glibc-static and libstdc++-static on fedora, centos.. which are on the powertools/crb repository).
# If the static build fails at the link stage, it might be because the static library is not provided
# for your distribution (look for libre2.a). See the Dockerfile for an example of how to build it.
BUILD_STATIC ?= 0

# List of plugins to build
PLUGINS ?= $(patsubst ./cmd/notification-%,%,$(wildcard ./cmd/notification-*))

# Can be overriden, if you can deal with the consequences
BUILD_REQUIRE_GO_MAJOR ?= 1
BUILD_REQUIRE_GO_MINOR ?= 21

#--------------------------------------

GO = go
GOTEST = $(GO) test

BUILD_CODENAME ?= alphaga

CROWDSEC_FOLDER = ./cmd/crowdsec
CSCLI_FOLDER = ./cmd/crowdsec-cli/
PLUGINS_DIR_PREFIX = ./cmd/notification-

CROWDSEC_BIN = crowdsec$(EXT)
CSCLI_BIN = cscli$(EXT)

# semver comparison to select the hub branch requires the version to start with "v"
ifneq ($(call substr,$(BUILD_VERSION),1,1),v)
    $(error BUILD_VERSION "$(BUILD_VERSION)" should start with "v")
endif

# Directory for the release files
RELDIR = crowdsec-$(BUILD_VERSION)

GO_MODULE_NAME = github.com/crowdsecurity/crowdsec

# Check if a given value is considered truthy and returns "0" or "1".
# A truthy value is one of the following: "1", "yes", or "true", case-insensitive.
#
# Usage:
# ifeq ($(call bool,$(FOO)),1)
# $(info Let's foo)
# endif
bool = $(if $(filter $(call lc, $1),1 yes true),1,0)

#--------------------------------------
#
# Define MAKE_FLAGS and LD_OPTS for the sub-makefiles in cmd/
#

MAKE_FLAGS = --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

LD_OPTS_VARS= \
-X 'github.com/crowdsecurity/go-cs-lib/version.Version=$(BUILD_VERSION)' \
-X 'github.com/crowdsecurity/go-cs-lib/version.BuildDate=$(BUILD_TIMESTAMP)' \
-X 'github.com/crowdsecurity/go-cs-lib/version.Tag=$(BUILD_TAG)' \
-X '$(GO_MODULE_NAME)/pkg/cwversion.Codename=$(BUILD_CODENAME)' \
-X '$(GO_MODULE_NAME)/pkg/csconfig.defaultConfigDir=$(DEFAULT_CONFIGDIR)' \
-X '$(GO_MODULE_NAME)/pkg/csconfig.defaultDataDir=$(DEFAULT_DATADIR)'

ifneq (,$(DOCKER_BUILD))
LD_OPTS_VARS += -X '$(GO_MODULE_NAME)/pkg/cwversion.System=docker'
endif

GO_TAGS := netgo,osusergo,sqlite_omit_load_extension

# this will be used by Go in the make target, some distributions require it
export PKG_CONFIG_PATH:=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH)

ifeq ($(call bool,$(BUILD_RE2_WASM)),0)
ifeq ($(PKG_CONFIG),)
  $(error "pkg-config is not available. Please install pkg-config.")
endif

ifeq ($(RE2_CHECK),)
RE2_FAIL := "libre2-dev is not installed, please install it or set BUILD_RE2_WASM=1 to use the WebAssembly version"
else
# += adds a space that we don't want
GO_TAGS := $(GO_TAGS),re2_cgo
LD_OPTS_VARS += -X '$(GO_MODULE_NAME)/pkg/cwversion.Libre2=C++'
endif
endif

# Build static to avoid the runtime dependency on libre2.so
ifeq ($(call bool,$(BUILD_STATIC)),1)
BUILD_TYPE = static
EXTLDFLAGS := -extldflags '-static'
else
BUILD_TYPE = dynamic
EXTLDFLAGS :=
endif

# Build with debug symbols, and disable optimizations + inlining, to use Delve
ifeq ($(call bool,$(DEBUG)),1)
STRIP_SYMBOLS :=
DISABLE_OPTIMIZATION := -gcflags "-N -l"
else
STRIP_SYMBOLS := -s -w
DISABLE_OPTIMIZATION :=
endif

export LD_OPTS=-ldflags "$(STRIP_SYMBOLS) $(EXTLDFLAGS) $(LD_OPTS_VARS)" \
	-trimpath -tags $(GO_TAGS) $(DISABLE_OPTIMIZATION)

ifeq ($(call bool,$(TEST_COVERAGE)),1)
LD_OPTS += -cover
endif

#--------------------------------------

.PHONY: build
build: pre-build goversion crowdsec cscli plugins  ## Build crowdsec, cscli and plugins

.PHONY: pre-build
pre-build:  ## Sanity checks and build information
	$(info Building $(BUILD_VERSION) ($(BUILD_TAG)) $(BUILD_TYPE) for $(GOOS)/$(GOARCH))

ifneq (,$(RE2_FAIL))
	$(error $(RE2_FAIL))
endif

ifneq (,$(RE2_CHECK))
	$(info Using C++ regexp library)
else
	$(info Fallback to WebAssembly regexp library. To use the C++ version, make sure you have installed libre2-dev and pkg-config.)
endif

ifeq ($(call bool,$(DEBUG)),1)
	$(info Building with debug symbols and disabled optimizations)
endif

ifeq ($(call bool,$(TEST_COVERAGE)),1)
	$(info Test coverage collection enabled)
endif

# intentional, empty line
	$(info )

.PHONY: all
all: clean test build  ## Clean, test and build (requires localstack)

.PHONY: plugins
plugins:  ## Build notification plugins
	@$(foreach plugin,$(PLUGINS), \
		$(MAKE) -C $(PLUGINS_DIR_PREFIX)$(plugin) build $(MAKE_FLAGS); \
	)

# same as "$(MAKE) -f debian/rules clean" but without the dependency on debhelper
.PHONY: clean-debian
clean-debian:
	@$(RM) -r debian/crowdsec
	@$(RM) -r debian/crowdsec
	@$(RM) -r debian/files
	@$(RM) -r debian/.debhelper
	@$(RM) -r debian/*.substvars
	@$(RM) -r debian/*-stamp

.PHONY: clean-rpm
clean-rpm:
	@$(RM) -r rpm/BUILD
	@$(RM) -r rpm/BUILDROOT
	@$(RM) -r rpm/RPMS
	@$(RM) -r rpm/SOURCES/*.tar.gz
	@$(RM) -r rpm/SRPMS

.PHONY: clean
clean: clean-debian clean-rpm testclean  ## Remove build artifacts
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean $(MAKE_FLAGS)
	@$(MAKE) -C $(CSCLI_FOLDER) clean $(MAKE_FLAGS)
	@$(RM) $(CROWDSEC_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(CSCLI_BIN) $(WIN_IGNORE_ERR)
	@$(RM) *.log $(WIN_IGNORE_ERR)
	@$(RM) crowdsec-release.tgz $(WIN_IGNORE_ERR)
	@$(foreach plugin,$(PLUGINS), \
		$(MAKE) -C $(PLUGINS_DIR_PREFIX)$(plugin) clean $(MAKE_FLAGS); \
	)

.PHONY: cscli
cscli: goversion  ## Build cscli
	@$(MAKE) -C $(CSCLI_FOLDER) build $(MAKE_FLAGS)

.PHONY: crowdsec
crowdsec: goversion  ## Build crowdsec
	@$(MAKE) -C $(CROWDSEC_FOLDER) build $(MAKE_FLAGS)


.PHONY: testclean
testclean: bats-clean  ## Remove test artifacts
	@$(RM) pkg/apiserver/ent $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/hubdir $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/install $(WIN_IGNORE_ERR)
	@$(RM) pkg/types/example.txt $(WIN_IGNORE_ERR)

# for the tests with localstack
export AWS_ENDPOINT_FORCE=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

testenv:
	@echo 'NOTE: You need Docker, docker-compose and run "make localstack" in a separate shell ("make localstack-stop" to terminate it)'

.PHONY: test
test: testenv goversion  ## Run unit tests with localstack
	$(GOTEST) $(LD_OPTS) ./...

.PHONY: go-acc
go-acc: testenv goversion  ## Run unit tests with localstack + coverage
	go-acc ./... -o coverage.out --ignore database,notifications,protobufs,cwversion,cstest,models -- $(LD_OPTS)

# mock AWS services
.PHONY: localstack
localstack:  ## Run localstack containers (required for unit testing)
	docker-compose -f test/localstack/docker-compose.yml up

.PHONY: localstack-stop
localstack-stop:  ## Stop localstack containers
	docker-compose -f test/localstack/docker-compose.yml down

# build vendor.tgz to be distributed with the release
.PHONY: vendor
vendor: vendor-remove  ## CI only - vendor dependencies and archive them for packaging
	$(GO) mod vendor
	tar czf vendor.tgz vendor
	tar --create --auto-compress --file=$(RELDIR)-vendor.tar.xz vendor

# remove vendor directories and vendor.tgz
.PHONY: vendor-remove
vendor-remove:  ## Remove vendor dependencies and archives
	$(RM) vendor vendor.tgz *-vendor.tar.xz

.PHONY: package
package:
	@echo "Building Release to dir $(RELDIR)"
	@$(MKDIR) $(RELDIR)/cmd/crowdsec
	@$(MKDIR) $(RELDIR)/cmd/crowdsec-cli
	@$(CP) $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@$(CP) $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli

	@$(foreach plugin,$(PLUGINS), \
		$(MKDIR) $(RELDIR)/$(PLUGINS_DIR_PREFIX)$(plugin); \
		$(CP) $(PLUGINS_DIR_PREFIX)$(plugin)/notification-$(plugin)$(EXT) $(RELDIR)/$(PLUGINS_DIR_PREFIX)$(plugin); \
		$(CP) $(PLUGINS_DIR_PREFIX)$(plugin)/$(plugin).yaml $(RELDIR)/$(PLUGINS_DIR_PREFIX)$(plugin)/; \
	)

	@$(CPR) ./config $(RELDIR)
	@$(CP) wizard.sh $(RELDIR)
	@$(CP) scripts/test_env.sh $(RELDIR)
	@$(CP) scripts/test_env.ps1 $(RELDIR)

	@tar cvzf crowdsec-release.tgz $(RELDIR)

.PHONY: check_release
check_release:
ifneq ($(OS), Windows_NT)
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, abort" ;  exit 1 ; fi
else
	@if (Test-Path -Path $(RELDIR)) { echo "$(RELDIR) already exists, abort" ;  exit 1 ; }
endif

.PHONY: release
release: check_release build package  ## Build a release tarball

.PHONY: windows_installer
windows_installer: build  ## Windows - build the installer
	@.\make_installer.ps1 -version $(BUILD_VERSION)

.PHONY: chocolatey
chocolatey: windows_installer  ## Windows - build the chocolatey package
	@.\make_chocolatey.ps1 -version $(BUILD_VERSION)

# Include test/bats.mk only if it exists
# to allow building without a test/ directory
# (i.e. inside docker)
ifeq (,$(wildcard test/bats.mk))
bats-clean:
else
include test/bats.mk
endif

include mk/goversion.mk
include mk/help.mk
