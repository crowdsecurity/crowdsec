SYSTEM?= $(shell uname -s | tr '[A-Z]' '[a-z]')

ifneq ("$(wildcard $(CURDIR)/platform/$(SYSTEM).mk)", "")
	include $(CURDIR)/platform/$(SYSTEM).mk
else
	include $(CURDIR)/platform/linux.mk
endif

CROWDSEC_FOLDER = "./cmd/crowdsec"
CSCLI_FOLDER = "./cmd/crowdsec-cli/"

HTTP_PLUGIN_FOLDER = "./plugins/notifications/http"
SLACK_PLUGIN_FOLDER = "./plugins/notifications/slack"
SPLUNK_PLUGIN_FOLDER = "./plugins/notifications/splunk"
EMAIL_PLUGIN_FOLDER = "./plugins/notifications/email"
DUMMY_PLUGIN_FOLDER = "./plugins/notifications/dummy"

HTTP_PLUGIN_BIN = "notification-http"
SLACK_PLUGIN_BIN = "notification-slack"
SPLUNK_PLUGIN_BIN = "notification-splunk"
EMAIL_PLUGIN_BIN = "notification-email"
DUMMY_PLUGIN_BIN= "notification-dummy"

HTTP_PLUGIN_CONFIG = "http.yaml"
SLACK_PLUGIN_CONFIG = "slack.yaml"
SPLUNK_PLUGIN_CONFIG = "splunk.yaml"
EMAIL_PLUGIN_CONFIG = "email.yaml"

CROWDSEC_BIN = "crowdsec"
CSCLI_BIN = "cscli"
BUILD_CMD = "build"

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Golang version info
GO_MAJOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 17
GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

# Current versioning information from env
BUILD_VERSION ?= "$(shell git describe --tags)"
BUILD_GOVERSION = "$(shell go version | cut -d " " -f3 | sed -E 's/[go]+//g')"
BUILD_CODENAME = $(shell cat RELEASE.json | jq -r .CodeName)
BUILD_TIMESTAMP = $(shell date +%F"_"%T)
BUILD_TAG ?= "$(shell git rev-parse HEAD)"
DEFAULT_CONFIGDIR ?= "/etc/crowdsec"
DEFAULT_DATADIR ?= "/var/lib/crowdsec/data"

LD_OPTS_VARS= \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/csconfig.defaultConfigDir=$(DEFAULT_CONFIGDIR) \
-X github.com/crowdsecurity/crowdsec/pkg/csconfig.defaultDataDir=$(DEFAULT_DATADIR)

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
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
        exit 0 ;\
    elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
        echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
        exit 1; \
    elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) ] ; then \
        echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
        exit 1; \
    fi

.PHONY: clean
clean: testclean
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean --no-print-directory
	@$(MAKE) -C $(CSCLI_FOLDER) clean --no-print-directory
	@$(RM) $(CROWDSEC_BIN)
	@$(RM) $(CSCLI_BIN)
	@$(RM) *.log
	@$(RM) crowdsec-release.tgz
	@$(RM) crowdsec-release-static.tgz
	@$(RM) $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN)
	@$(RM) $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN)
	@$(RM) $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN)
	@$(RM) $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN)
	@$(RM) $(DUMMY_PLUGIN_FOLDER)/$(DUMMY_PLUGIN_BIN)


cscli: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) build --no-print-directory

cscli-bincover: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) build-bincover --no-print-directory

crowdsec: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) build --no-print-directory

crowdsec-bincover: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) build-bincover --no-print-directory

http-plugin: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(HTTP_PLUGIN_FOLDER) build --no-print-directory

slack-plugin: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(SLACK_PLUGIN_FOLDER) build --no-print-directory

splunk-plugin: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(SPLUNK_PLUGIN_FOLDER) build --no-print-directory

email-plugin: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(EMAIL_PLUGIN_FOLDER) build --no-print-directory

dummy-plugin: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(DUMMY_PLUGIN_FOLDER) build --no-print-directory

cscli_static: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) static --no-print-directory

crowdsec_static: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) static --no-print-directory

http-plugin_static: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(HTTP_PLUGIN_FOLDER) static --no-print-directory

slack-plugin_static: goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(SLACK_PLUGIN_FOLDER) static --no-print-directory

splunk-plugin_static:goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(SPLUNK_PLUGIN_FOLDER) static --no-print-directory

email-plugin_static:goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(EMAIL_PLUGIN_FOLDER) static --no-print-directory

dummy-plugin_static:goversion
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(DUMMY_PLUGIN_FOLDER) static --no-print-directory

.PHONY: testclean
testclean: bats-clean
	@$(RM) pkg/apiserver/ent
	@$(RM) -r pkg/cwhub/hubdir

.PHONY: test
test: goversion
	$(GOTEST) $(LD_OPTS) ./...

package-common:
	@echo Building Release to dir $(RELDIR)
	@mkdir -p $(RELDIR)/cmd/crowdsec
	@mkdir -p $(RELDIR)/cmd/crowdsec-cli
	@mkdir -p $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@mkdir -p $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@mkdir -p $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@mkdir -p $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@cp $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@cp $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli

	@cp $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@cp $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@cp $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@cp $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN) $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@cp $(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(HTTP_PLUGIN_FOLDER))
	@cp $(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(SLACK_PLUGIN_FOLDER))
	@cp $(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(SPLUNK_PLUGIN_FOLDER))
	@cp $(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_CONFIG) $(RELDIR)/$(subst ./,,$(EMAIL_PLUGIN_FOLDER))

	@cp -R ./config $(RELDIR)
	@cp wizard.sh $(RELDIR)
	@cp scripts/test_env.sh $(RELDIR)

.PHONY: package
package: package-common
	@tar cvzf crowdsec-release.tgz $(RELDIR)

package_static: package-common
	@tar cvzf crowdsec-release-static.tgz $(RELDIR)

.PHONY: check_release
check_release:
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, abort" ;  exit 1 ; fi

.PHONY: release
release: check_release build package

.PHONY: release_static
release_static: check_release static package_static

include tests/bats.mk

