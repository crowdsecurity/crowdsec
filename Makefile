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

# List of notification plugins to build
PLUGINS ?= $(patsubst ./cmd/notification-%,%,$(wildcard ./cmd/notification-*))

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
LD_OPTS_VARS += -X 'github.com/crowdsecurity/go-cs-lib/version.System=docker'
endif

#expr_debug tag is required to enable the debug mode in expr
GO_TAGS := netgo,osusergo,sqlite_omit_load_extension,expr_debug

# Allow building on ubuntu 24.10, see https://github.com/golang/go/issues/70023
export CGO_LDFLAGS_ALLOW=-Wl,--(push|pop)-state.*

# this will be used by Go in the make target, some distributions require it
export PKG_CONFIG_PATH:=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH)

#--------------------------------------
#
# Choose the re2 backend.
#

ifeq ($(call bool,$(BUILD_RE2_WASM)),0)
ifeq ($(PKG_CONFIG),)
  $(error "pkg-config is not available. Please install pkg-config.")
endif

ifeq ($(RE2_CHECK),)
RE2_FAIL := "libre2-dev is not installed, please install it or set BUILD_RE2_WASM=1 to use the WebAssembly version"
# if you prefer to build WASM instead of a critical error, comment out RE2_FAIL and uncomment RE2_MSG.
# RE2_MSG := Fallback to WebAssembly regexp library. To use the C++ version, make sure you have installed libre2-dev and pkg-config.
else
# += adds a space that we don't want
GO_TAGS := $(GO_TAGS),re2_cgo
LD_OPTS_VARS += -X '$(GO_MODULE_NAME)/pkg/cwversion.Libre2=C++'
RE2_MSG := Using C++ regexp library
endif
else
RE2_MSG := Using WebAssembly regexp library
endif

ifeq ($(call bool,$(BUILD_RE2_WASM)),1)
else
ifneq (,$(RE2_CHECK))
endif
endif

#--------------------------------------
#
# Handle optional components and build profiles, to save space on the final binaries.
#
# Keep it safe for now until we decide how to expand on the idea. Either choose a profile or exclude components manually.
# For example if we want to disable some component by default, or have opt-in components (INCLUDE?).

ifeq ($(and $(BUILD_PROFILE),$(EXCLUDE)),1)
$(error "Cannot specify both BUILD_PROFILE and EXCLUDE")
endif

COMPONENTS := \
	datasource_appsec \
	datasource_cloudwatch \
	datasource_docker \
	datasource_file \
	datasource_http \
	datasource_k8saudit \
	datasource_kafka \
	datasource_journalctl \
	datasource_kinesis \
	datasource_loki \
	datasource_victorialogs \
	datasource_s3 \
	datasource_syslog \
	datasource_wineventlog \
	cscli_setup

comma := ,
space := $(empty) $(empty)

# Predefined profiles

# keep only datasource-file
EXCLUDE_MINIMAL := $(subst $(space),$(comma),$(filter-out datasource_file,,$(COMPONENTS)))

# example
# EXCLUDE_MEDIUM := datasource_kafka,datasource_kinesis,datasource_s3

BUILD_PROFILE ?= default

# Set the EXCLUDE_LIST based on the chosen profile, unless EXCLUDE is already set
ifeq ($(BUILD_PROFILE),minimal)
EXCLUDE ?= $(EXCLUDE_MINIMAL)
else ifneq ($(BUILD_PROFILE),default)
$(error Invalid build profile specified: $(BUILD_PROFILE). Valid profiles are: minimal, default)
endif

# Create list of excluded components from the EXCLUDE variable
EXCLUDE_LIST := $(subst $(comma),$(space),$(EXCLUDE))

INVALID_COMPONENTS := $(filter-out $(COMPONENTS),$(EXCLUDE_LIST))
ifneq ($(INVALID_COMPONENTS),)
$(error Invalid optional components specified in EXCLUDE: $(INVALID_COMPONENTS). Valid components are: $(COMPONENTS))
endif

# Convert the excluded components to "no_<component>" form
COMPONENT_TAGS := $(foreach component,$(EXCLUDE_LIST),no_$(component))

ifneq ($(COMPONENT_TAGS),)
GO_TAGS := $(GO_TAGS),$(subst $(space),$(comma),$(COMPONENT_TAGS))
endif

#--------------------------------------

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
STRIP_SYMBOLS := -s
DISABLE_OPTIMIZATION :=
endif

export LD_OPTS=-ldflags "$(STRIP_SYMBOLS) $(EXTLDFLAGS) $(LD_OPTS_VARS)" \
	-trimpath -tags $(GO_TAGS) $(DISABLE_OPTIMIZATION)

ifeq ($(call bool,$(TEST_COVERAGE)),1)
LD_OPTS += -cover
endif

#--------------------------------------

.PHONY: build
build: build-info crowdsec cscli plugins  ## Build crowdsec, cscli and plugins

.PHONY: build-info
build-info:  ## Print build information
	$(info Building $(BUILD_VERSION) ($(BUILD_TAG)) $(BUILD_TYPE) for $(GOOS)/$(GOARCH))
	$(info Excluded components: $(if $(EXCLUDE_LIST),$(EXCLUDE_LIST),none))

ifneq (,$(RE2_FAIL))
	$(error $(RE2_FAIL))
endif

	$(info $(RE2_MSG))

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
cscli:  ## Build cscli
	@$(MAKE) -C $(CSCLI_FOLDER) build $(MAKE_FLAGS)

.PHONY: crowdsec
crowdsec:  ## Build crowdsec
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
	@echo 'NOTE: You need to run "make localstack" in a separate shell, "make localstack-stop" to terminate it'

.PHONY: test
test: testenv  ## Run unit tests with localstack
	$(GOTEST) --tags=$(GO_TAGS) $(LD_OPTS) ./...

.PHONY: go-acc
go-acc: testenv  ## Run unit tests with localstack + coverage
	go-acc ./... -o coverage.out --ignore database,notifications,protobufs,cwversion,cstest,models --tags $(GO_TAGS) -- $(LD_OPTS)

check_docker:
	@if ! docker info > /dev/null 2>&1; then \
		echo "Could not run 'docker info': check that docker is running, and if you need to run this command with sudo."; \
	fi

# mock AWS services
.PHONY: localstack
localstack: check_docker  ## Run localstack containers (required for unit testing)
	docker compose -f test/localstack/docker-compose.yml up

.PHONY: localstack-stop
localstack-stop: check_docker  ## Stop localstack containers
	docker compose -f test/localstack/docker-compose.yml down

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

include mk/help.mk
