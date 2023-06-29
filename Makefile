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
# The WASM version works just as well but might have performance issues, XXX: clarify
# so it is not recommended for production use.
BUILD_RE2_WASM ?= 0

# To build static binaries, run "make BUILD_STATIC=1".
# On some platforms, this requires
# additional packages (e.g. glibc-static and libstdc++-static on fedora, centos..).
# If the static build fails at the link stage, it might be because the static library is not provided
# for your distribution (look for libre2.a). See the Dockerfile for an example of how to build it.
BUILD_STATIC ?= 0

# List of plugins to build
PLUGINS ?= $(patsubst ./plugins/notifications/%,%,$(wildcard ./plugins/notifications/*))

# Can be overriden, if you can deal with the consequences
BUILD_REQUIRE_GO_MAJOR ?= 1
BUILD_REQUIRE_GO_MINOR ?= 20

#--------------------------------------

GOCMD = go
GOTEST = $(GOCMD) test

BUILD_CODENAME ?= alphaga

CROWDSEC_FOLDER = ./cmd/crowdsec
CSCLI_FOLDER = ./cmd/crowdsec-cli/
PLUGINS_DIR = ./plugins/notifications

CROWDSEC_BIN = crowdsec$(EXT)
CSCLI_BIN = cscli$(EXT)

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
# Define MAKE_FLAGS and LD_OPTS for the sub-makefiles in cmd/ and plugins/
#

MAKE_FLAGS = --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

LD_OPTS_VARS= \
-X 'github.com/crowdsecurity/go-cs-lib/pkg/version.Version=$(BUILD_VERSION)' \
-X 'github.com/crowdsecurity/go-cs-lib/pkg/version.BuildDate=$(BUILD_TIMESTAMP)' \
-X 'github.com/crowdsecurity/go-cs-lib/pkg/version.Tag=$(BUILD_TAG)' \
-X '$(GO_MODULE_NAME)/pkg/cwversion.Codename=$(BUILD_CODENAME)' \
-X '$(GO_MODULE_NAME)/pkg/csconfig.defaultConfigDir=$(DEFAULT_CONFIGDIR)' \
-X '$(GO_MODULE_NAME)/pkg/csconfig.defaultDataDir=$(DEFAULT_DATADIR)'

ifneq (,$(DOCKER_BUILD))
LD_OPTS_VARS += -X '$(GO_MODULE_NAME)/pkg/cwversion.System=docker'
endif

GO_TAGS := netgo,osusergo,sqlite_omit_load_extension
# this will be used by Go in the make target
export PKG_CONFIG_PATH:=/usr/local/lib/pkgconfig:$(PKG_CONFIG_PATH)

ifeq ($(call bool,$(BUILD_RE2_WASM)),0)
ifeq ($(PKG_CONFIG),)
  $(error "pkg-config is not available. Please install pkg-config.")
endif

ifeq ($(RE2_CHECK),)
# we could detect the platform and suggest the command to install
RE2_FAIL := "libre2-dev is not installed, please install it or set BUILD_RE2_WASM=1 to use the WebAssembly version"
else
# += adds a space that we don't want
GO_TAGS := $(GO_TAGS),re2_cgo
LD_OPTS_VARS += -X '$(GO_MODULE_NAME)/pkg/cwversion.Libre2=C++'
endif
endif

ifeq ($(call bool,$(BUILD_STATIC)),1)
BUILD_TYPE = static
EXTLDFLAGS := -extldflags '-static'
else
BUILD_TYPE = dynamic
EXTLDFLAGS :=
endif

export LD_OPTS=-ldflags "-s -w $(EXTLDFLAGS) $(LD_OPTS_VARS)" \
	-trimpath -tags $(GO_TAGS)

ifneq (,$(TEST_COVERAGE))
LD_OPTS += -cover
endif

#--------------------------------------

.PHONY: build
build: pre-build goversion crowdsec cscli plugins

.PHONY: pre-build
pre-build:
	$(info Building $(BUILD_VERSION) ($(BUILD_TAG)) $(BUILD_TYPE) for $(GOOS)/$(GOARCH))

ifneq (,$(RE2_FAIL))
	$(error $(RE2_FAIL))
endif

ifneq (,$(RE2_CHECK))
	$(info Using C++ regexp library)
else
	$(info Fallback to WebAssembly regexp library. To use the C++ version, make sure you have installed libre2-dev and pkg-config.)
endif
	$(info )

.PHONY: all
all: clean test build

.PHONY: plugins
plugins:
	@$(foreach plugin,$(PLUGINS), \
		$(MAKE) -C $(PLUGINS_DIR)/$(plugin) build $(MAKE_FLAGS); \
	)

.PHONY: clean
clean: testclean
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean $(MAKE_FLAGS)
	@$(MAKE) -C $(CSCLI_FOLDER) clean $(MAKE_FLAGS)
	@$(RM) $(CROWDSEC_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(CSCLI_BIN) $(WIN_IGNORE_ERR)
	@$(RM) *.log $(WIN_IGNORE_ERR)
	@$(RM) crowdsec-release.tgz $(WIN_IGNORE_ERR)
	@$(foreach plugin,$(PLUGINS), \
		$(MAKE) -C $(PLUGINS_DIR)/$(plugin) clean $(MAKE_FLAGS); \
	)

.PHONY: cscli
cscli: goversion
	@$(MAKE) -C $(CSCLI_FOLDER) build $(MAKE_FLAGS)

.PHONY: crowdsec
crowdsec: goversion
	@$(MAKE) -C $(CROWDSEC_FOLDER) build $(MAKE_FLAGS)

.PHONY: testclean
testclean: bats-clean
	@$(RM) pkg/apiserver/ent $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/hubdir $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/install $(WIN_IGNORE_ERR)
	@$(RM) pkg/types/example.txt $(WIN_IGNORE_ERR)

export AWS_ENDPOINT_FORCE=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

testenv:
	@echo 'NOTE: You need Docker, docker-compose and run "make localstack" in a separate shell ("make localstack-stop" to terminate it)'

.PHONY: test
test: testenv goversion
	$(GOTEST) $(LD_OPTS) ./...

.PHONY: go-acc
go-acc: testenv goversion
	go-acc ./... -o coverage.out --ignore database,notifications,protobufs,cwversion,cstest,models -- $(LD_OPTS) | \
		sed 's/ *coverage:.*of statements in.*//'

.PHONY: localstack
localstack:
	docker-compose -f test/localstack/docker-compose.yml up

.PHONY: localstack-stop
localstack-stop:
	docker-compose -f test/localstack/docker-compose.yml down

# list of plugins that contain go.mod
PLUGIN_VENDOR = $(foreach plugin,$(PLUGINS),$(shell if [ -f $(PLUGINS_DIR)/$(plugin)/go.mod ]; then echo $(PLUGINS_DIR)/$(plugin); fi))

.PHONY: vendor
vendor:
	$(foreach plugin_dir,$(PLUGIN_VENDOR), \
		cd $(plugin_dir) >/dev/null && \
		$(GOCMD) mod vendor && \
		cd - >/dev/null; \
	)
	$(GOCMD) mod vendor
	tar -czf vendor.tgz vendor $(foreach plugin_dir,$(PLUGIN_VENDOR),$(plugin_dir)/vendor)

.PHONY: vendor-remove
vendor-remove:
	$(foreach plugin_dir,$(PLUGIN_VENDOR), \
		$(RM) $(plugin_dir)/vendor; \
	)
	$(RM) vendor vendor.tgz

.PHONY: package
package:
	@echo "Building Release to dir $(RELDIR)"
	@$(MKDIR) $(RELDIR)/cmd/crowdsec
	@$(MKDIR) $(RELDIR)/cmd/crowdsec-cli
	@$(CP) $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@$(CP) $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli

	@$(foreach plugin,$(PLUGINS), \
		$(MKDIR) $(RELDIR)/$(PLUGINS_DIR)/$(plugin); \
		$(CP) $(PLUGINS_DIR)/$(plugin)/notification-$(plugin)$(EXT) $(RELDIR)/$(PLUGINS_DIR)/$(plugin); \
		$(CP) $(PLUGINS_DIR)/$(plugin)/$(plugin).yaml $(RELDIR)/$(PLUGINS_DIR)/$(plugin)/; \
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
release: check_release build package

.PHONY: windows_installer
windows_installer: build
	@.\make_installer.ps1 -version $(BUILD_VERSION)

.PHONY: chocolatey
chocolatey: windows_installer
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
