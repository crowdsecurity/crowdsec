ifeq ($(OS),Windows_NT)
SHELL := pwsh.exe
.SHELLFLAGS := -NoProfile -Command
ROOT= $(shell (Get-Location).Path)
SYSTEM=windows
EXT=.exe
else
ROOT?= $(shell pwd)
SYSTEM?= $(shell uname -s | tr '[A-Z]' '[a-z]')
endif

ifneq ("$(wildcard $(CURDIR)/platform/$(SYSTEM).mk)", "")
	include $(CURDIR)/platform/$(SYSTEM).mk
else
	include $(CURDIR)/platform/linux.mk
endif

ifneq ($(OS),Windows_NT)
	include $(ROOT)/platform/unix_common.mk
endif

CROWDSEC_FOLDER = ./cmd/crowdsec
CSCLI_FOLDER = ./cmd/crowdsec-cli/

HTTP_PLUGIN_FOLDER = ./plugins/notifications/http
SLACK_PLUGIN_FOLDER = ./plugins/notifications/slack
SPLUNK_PLUGIN_FOLDER = ./plugins/notifications/splunk
EMAIL_PLUGIN_FOLDER = ./plugins/notifications/email
DUMMY_PLUGIN_FOLDER = ./plugins/notifications/dummy

HTTP_PLUGIN_BIN = notification-http$(EXT)
SLACK_PLUGIN_BIN = notification-slack$(EXT)
SPLUNK_PLUGIN_BIN = notification-splunk$(EXT)
EMAIL_PLUGIN_BIN = notification-email$(EXT)
DUMMY_PLUGIN_BIN= notification-dummy$(EXT)

HTTP_PLUGIN_CONFIG = http.yaml
SLACK_PLUGIN_CONFIG = slack.yaml
SPLUNK_PLUGIN_CONFIG = splunk.yaml
EMAIL_PLUGIN_CONFIG = email.yaml

CROWDSEC_BIN = crowdsec$(EXT)
CSCLI_BIN = cscli$(EXT)
BUILD_CMD = build

# Go should not be required to run functional tests
GOOS ?= $(shell command -v go >/dev/null && go env GOOS)
GOARCH ?= $(shell command -v go >/dev/null && go env GOARCH)

MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 17
GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

LD_OPTS_VARS= \
-X github.com/crowdsecurity/crowdsec/cmd/crowdsec.bincoverTesting=$(BINCOVER_TESTING) \
-X github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli.bincoverTesting=$(BINCOVER_TESTING) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.GoVersion=$(BUILD_GOVERSION) \
-X 'github.com/crowdsecurity/crowdsec/pkg/csconfig.defaultConfigDir=$(DEFAULT_CONFIGDIR)' \
-X 'github.com/crowdsecurity/crowdsec/pkg/csconfig.defaultDataDir=$(DEFAULT_DATADIR)'

export LD_OPTS=-ldflags "-s -w $(LD_OPTS_VARS)"
export LD_OPTS_STATIC=-ldflags "-s -w $(LD_OPTS_VARS) -extldflags '-static'"

GOCMD=go
GOTEST=$(GOCMD) test

RELDIR = crowdsec-$(BUILD_VERSION)

.PHONY: build
build: goversion crowdsec cscli plugins

.PHONY: all
all: clean test build

.PHONY: static
static: crowdsec_static cscli_static plugins_static

.PHONY: plugins
plugins: http-plugin slack-plugin splunk-plugin email-plugin dummy-plugin

plugins_static: http-plugin_static slack-plugin_static splunk-plugin_static email-plugin_static dummy-plugin_static

goversion:
ifneq ($(OS),Windows_NT)
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
        exit 0 ;\
    elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
        echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
        exit 1; \
    elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) ] ; then \
        echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
        exit 1; \
    fi
else
#This needs Set-ExecutionPolicy -Scope CurrentUser Unrestricted
	@$(ROOT)/scripts/check_go_version.ps1 $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) $(MINIMUM_SUPPORTED_GO_MINOR_VERSION)
endif

.PHONY: clean
clean: testclean
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean --no-print-directory RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"
	@$(MAKE) -C $(CSCLI_FOLDER) clean --no-print-directory RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"
	@$(RM) $(CROWDSEC_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(CSCLI_BIN) $(WIN_IGNORE_ERR)
	@$(RM) *.log $(WIN_IGNORE_ERR)
	@$(RM) crowdsec-release.tgz $(WIN_IGNORE_ERR)
	@$(RM) crowdsec-release-static.tgz $(WIN_IGNORE_ERR)
	@$(RM) $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(DUMMY_PLUGIN_FOLDER)/$(DUMMY_PLUGIN_BIN) $(WIN_IGNORE_ERR)


cscli: goversion
	@$(MAKE) -C $(CSCLI_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

cscli-bincover: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) build-bincover --no-print-directory

crowdsec: goversion
	@$(MAKE) -C $(CROWDSEC_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

crowdsec-bincover: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) build-bincover --no-print-directory

http-plugin: goversion
	@$(MAKE) -C $(HTTP_PLUGIN_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

slack-plugin: goversion
	@$(MAKE) -C $(SLACK_PLUGIN_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

splunk-plugin: goversion
	@$(MAKE) -C $(SPLUNK_PLUGIN_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

email-plugin: goversion
	@$(MAKE) -C $(EMAIL_PLUGIN_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

dummy-plugin: goversion
	$(MAKE) -C $(DUMMY_PLUGIN_FOLDER) build --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

cscli_static: goversion
	@$(MAKE) -C $(CSCLI_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

crowdsec_static: goversion
	@$(MAKE) -C $(CROWDSEC_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

http-plugin_static: goversion
	@$(MAKE) -C $(HTTP_PLUGIN_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

slack-plugin_static: goversion
	@$(MAKE) -C $(SLACK_PLUGIN_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

splunk-plugin_static:goversion
	@$(MAKE) -C $(SPLUNK_PLUGIN_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

email-plugin_static:goversion
	@$(MAKE) -C $(EMAIL_PLUGIN_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

dummy-plugin_static:goversion
	$(MAKE) -C $(DUMMY_PLUGIN_FOLDER) static --no-print-directory GOARCH=$(GOARCH) GOOS=$(GOOS) RM="$(RM)" WIN_IGNORE_ERR="$(WIN_IGNORE_ERR)" CP="$(CP)" CPR="$(CPR)" MKDIR="$(MKDIR)"

.PHONY: testclean
testclean: bats-clean
	@$(RM) pkg/apiserver/ent $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/hubdir $(WIN_IGNORE_ERR)
	@$(RM) pkg/cwhub/install $(WIN_IGNORE_ERR)
	@$(RM) pkg/types/example.txt $(WIN_IGNORE_ERR)

.PHONY: test
test: export AWS_ENDPOINT_FORCE=http://localhost:4566
test: goversion
	@echo 'NOTE: You need Docker, docker-compose and run "make localstack" in a separate shell ("make localstack-stop" to terminate it)'
	$(GOTEST) $(LD_OPTS) ./...

.PHONY: localstack
localstack:
	docker-compose -f tests/localstack/docker-compose.yml up

.PHONY: localstack-stop
localstack-stop:
	docker-compose -f tests/localstack/docker-compose.yml down

package-common:
	@echo "Building Release to dir $(RELDIR)"
	@$(MKDIR) $(RELDIR)/cmd/crowdsec
	@$(MKDIR) $(RELDIR)/cmd/crowdsec-cli
	@$(MKDIR) $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@$(MKDIR) $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@$(MKDIR) $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@$(MKDIR) $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@$(CP) $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@$(CP) $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli

	@$(CP) $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@$(CP) $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@$(CP) $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@$(CP) $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@$(CP) $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@$(CP) $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@$(CP) $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@$(CP) $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@$(CPR) ./config $(RELDIR)
	@$(CP) wizard.sh $(RELDIR)
	@$(CP) scripts/test_env.sh $(RELDIR)
	@$(CP) scripts/test_env.ps1 $(RELDIR)

.PHONY: package
package: package-common
	@tar cvzf crowdsec-release.tgz $(RELDIR)

package_static: package-common
	@tar cvzf crowdsec-release-static.tgz $(RELDIR)

.PHONY: check_release
check_release:
ifneq ($(OS),Windows_NT)
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, abort" ;  exit 1 ; fi
else
	@if (Test-Path -Path $(RELDIR)) { echo "$(RELDIR) already exists, abort" ;  exit 1 ; }
endif

.PHONY: release
release: check_release build package

.PHONY: release_static
release_static: check_release static package_static

.PHONY: windows_installer
windows_installer: build
	@.\make_installer.ps1 -version $(BUILD_VERSION)

.PHONY: chocolatey
chocolatey: windows_installer
	@.\make_chocolatey.ps1 -version $(BUILD_VERSION)

include tests/bats.mk
