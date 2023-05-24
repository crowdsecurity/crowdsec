include mk/platform.mk

BUILD_CODENAME ?= alphaga

CROWDSEC_FOLDER = ./cmd/crowdsec
CSCLI_FOLDER = ./cmd/crowdsec-cli/

HTTP_PLUGIN_FOLDER = plugins/notifications/http
SLACK_PLUGIN_FOLDER = plugins/notifications/slack
SPLUNK_PLUGIN_FOLDER = plugins/notifications/splunk
EMAIL_PLUGIN_FOLDER = plugins/notifications/email
DUMMY_PLUGIN_FOLDER = plugins/notifications/dummy

HTTP_PLUGIN_BIN = notification-http$(EXT)
SLACK_PLUGIN_BIN = notification-slack$(EXT)
SPLUNK_PLUGIN_BIN = notification-splunk$(EXT)
EMAIL_PLUGIN_BIN = notification-email$(EXT)
DUMMY_PLUGIN_BIN = notification-dummy$(EXT)

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
build: goversion crowdsec cscli plugins

.PHONY: all
all: clean test build

.PHONY: plugins
plugins: http-plugin slack-plugin splunk-plugin email-plugin dummy-plugin

.PHONY: clean
clean: testclean
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean $(MAKE_FLAGS)
	@$(MAKE) -C $(CSCLI_FOLDER) clean $(MAKE_FLAGS)
	@$(RM) $(CROWDSEC_BIN) $(WIN_IGNORE_ERR)
	@$(RM) $(CSCLI_BIN) $(WIN_IGNORE_ERR)
	@$(RM) *.log $(WIN_IGNORE_ERR)
	@$(RM) crowdsec-release.tgz $(WIN_IGNORE_ERR)
	@$(RM) ./$(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) ./$(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) ./$(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) ./$(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN) $(WIN_IGNORE_ERR)
	@$(RM) ./$(DUMMY_PLUGIN_FOLDER)/$(DUMMY_PLUGIN_BIN) $(WIN_IGNORE_ERR)


cscli: goversion
	@$(MAKE) -C $(CSCLI_FOLDER) build $(MAKE_FLAGS)

crowdsec: goversion
	@$(MAKE) -C $(CROWDSEC_FOLDER) build $(MAKE_FLAGS)

http-plugin: goversion
	@$(MAKE) -C ./$(HTTP_PLUGIN_FOLDER) build $(MAKE_FLAGS)

slack-plugin: goversion
	@$(MAKE) -C ./$(SLACK_PLUGIN_FOLDER) build $(MAKE_FLAGS)

splunk-plugin: goversion
	@$(MAKE) -C ./$(SPLUNK_PLUGIN_FOLDER) build $(MAKE_FLAGS)

email-plugin: goversion
	@$(MAKE) -C ./$(EMAIL_PLUGIN_FOLDER) build $(MAKE_FLAGS)

dummy-plugin: goversion
	$(MAKE) -C ./$(DUMMY_PLUGIN_FOLDER) build $(MAKE_FLAGS)

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

package-common:
	@echo "Building Release to dir $(RELDIR)"
	@$(MKDIR) $(RELDIR)/cmd/crowdsec
	@$(MKDIR) $(RELDIR)/cmd/crowdsec-cli
	@$(MKDIR) $(RELDIR)/$(HTTP_PLUGIN_FOLDER)
	@$(MKDIR) $(RELDIR)/$(SLACK_PLUGIN_FOLDER)
	@$(MKDIR) $(RELDIR)/$(SPLUNK_PLUGIN_FOLDER)
	@$(MKDIR) $(RELDIR)/$(EMAIL_PLUGIN_FOLDER)

	@$(CP) $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@$(CP) $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli

	@$(CP) ./$(HTTP_PLUGIN_FOLDER)/$(HTTP_PLUGIN_BIN) $(RELDIR)/$(HTTP_PLUGIN_FOLDER)
	@$(CP) ./$(SLACK_PLUGIN_FOLDER)/$(SLACK_PLUGIN_BIN) $(RELDIR)/$(SLACK_PLUGIN_FOLDER)
	@$(CP) ./$(SPLUNK_PLUGIN_FOLDER)/$(SPLUNK_PLUGIN_BIN) $(RELDIR)/$(SPLUNK_PLUGIN_FOLDER)
	@$(CP) ./$(EMAIL_PLUGIN_FOLDER)/$(EMAIL_PLUGIN_BIN) $(RELDIR)/$(EMAIL_PLUGIN_FOLDER)

	@$(CP) ./$(HTTP_PLUGIN_FOLDER)/http.yaml $(RELDIR)/$(HTTP_PLUGIN_FOLDER)
	@$(CP) ./$(SLACK_PLUGIN_FOLDER)/slack.yaml $(RELDIR)/$(SLACK_PLUGIN_FOLDER)
	@$(CP) ./$(SPLUNK_PLUGIN_FOLDER)/splunk.yaml $(RELDIR)/$(SPLUNK_PLUGIN_FOLDER)
	@$(CP) ./$(EMAIL_PLUGIN_FOLDER)/email.yaml $(RELDIR)/$(EMAIL_PLUGIN_FOLDER)

	@$(CPR) ./config $(RELDIR)
	@$(CP) wizard.sh $(RELDIR)
	@$(CP) scripts/test_env.sh $(RELDIR)
	@$(CP) scripts/test_env.ps1 $(RELDIR)

.PHONY: package
package: package-common
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
