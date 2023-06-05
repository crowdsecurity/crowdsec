include mk/platform.mk

BUILD_REQUIRE_GO_MAJOR ?= 1
BUILD_REQUIRE_GO_MINOR ?= 20

BUILD_CODENAME ?= alphaga

CROWDSEC_FOLDER = ./cmd/crowdsec
CSCLI_FOLDER = ./cmd/crowdsec-cli/

PLUGINS ?= $(patsubst ./plugins/notifications/%,%,$(wildcard ./plugins/notifications/*))
PLUGINS_DIR = ./plugins/notifications

CROWDSEC_BIN = crowdsec$(EXT)
CSCLI_BIN = cscli$(EXT)

GO_MODULE_NAME = github.com/crowdsecurity/crowdsec

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

ifdef BUILD_STATIC
$(warning WARNING: The BUILD_STATIC variable is deprecated and has no effect. Builds are static by default since v1.5.0.)
endif

export LD_OPTS=-ldflags "-s -w -extldflags '-static' $(LD_OPTS_VARS)" \
	-trimpath -tags netgo,osusergo,sqlite_omit_load_extension

ifneq (,$(TEST_COVERAGE))
LD_OPTS += -cover
endif

GOCMD = go
GOTEST = $(GOCMD) test

RELDIR = crowdsec-$(BUILD_VERSION)

# flags for sub-makefiles
MAKE_FLAGS = --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

.PHONY: build
build: pre-build goversion crowdsec cscli plugins

pre-build:
	$(info Building $(BUILD_VERSION) ($(BUILD_TAG)) for $(GOOS)/$(GOARCH))
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


cscli: goversion
	@$(MAKE) -C $(CSCLI_FOLDER) build $(MAKE_FLAGS)

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

.PHONY: vendor
vendor:
	@echo "Vendoring dependencies"
	@$(GOCMD) mod vendor
	@$(foreach plugin,$(PLUGINS), \
		$(MAKE) -C $(PLUGINS_DIR)/$(plugin) vendor $(MAKE_FLAGS); \
	)

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
