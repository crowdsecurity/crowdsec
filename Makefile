ROOT= $(shell pwd)
SYSTEM?= $(shell uname -s | tr '[A-Z]' '[a-z]')

ifneq ("$(wildcard $(ROOT)/platform/$(SYSTEM).mk)", "")
	include $(ROOT)/platform/$(SYSTEM).mk
else
	include $(ROOT)/platform/linux.mk
endif

PREFIX?="/tmp/crowdsec/"
CFG_PREFIX = $(PREFIX)"/etc/crowdsec/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"
DATA_PREFIX = $(PREFIX)"/var/run/crowdsec/"

PID_DIR = $(PREFIX)"/var/run/"
CROWDSEC_FOLDER = "./cmd/crowdsec"
CSCLI_FOLDER = "./cmd/crowdsec-cli/"
CROWDSEC_BIN = "crowdsec"
CSCLI_BIN = "cscli"
BUILD_CMD = "build"

GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)

#Golang version info
GO_MAJOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 13
GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)
#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags `git rev-list --tags --max-count=1`)"
BUILD_GOVERSION="$(shell go version | cut -d " " -f3 | sed -E 's/[go]+//g')"
BUILD_CODENAME=$(shell cat RELEASE.json | jq -r .CodeName)
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"

export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.System=$(SYSTEM) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME)  \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.GoVersion=$(BUILD_GOVERSION)"

export LD_OPTS_STATIC=-ldflags "-s -w -X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME)  \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.GoVersion=$(BUILD_GOVERSION) \
-extldflags '-static'"

RELDIR = crowdsec-$(BUILD_VERSION)

all: clean test build

build: goversion crowdsec cscli

static: goversion crowdsec_static cscli_static

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

clean:
	@$(MAKE) -C $(CROWDSEC_FOLDER) clean --no-print-directory
	@$(MAKE) -C $(CSCLI_FOLDER) clean --no-print-directory
	@rm -f $(CROWDSEC_BIN)
	@rm -f $(CSCLI_BIN)
	@rm -f *.log
	@rm -f crowdsec-release.tgz

cscli:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) build --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


crowdsec:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) build --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


cscli_static:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CSCLI_FOLDER) static --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


crowdsec_static:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@GOARCH=$(GOARCH) GOOS=$(GOOS) $(MAKE) -C $(CROWDSEC_FOLDER) static --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif

#.PHONY: test
test:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@$(MAKE) -C $(CROWDSEC_FOLDER) test --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif

.PHONY: check_release
check_release:
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, abort" ;  exit 1 ; fi

.PHONY:
release: check_release build
	@echo Building Release to dir $(RELDIR)
	@mkdir -p $(RELDIR)/cmd/crowdsec
	@mkdir -p $(RELDIR)/cmd/crowdsec-cli
	@cp $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@cp $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli
	@cp -R ./config/ $(RELDIR)
	@cp wizard.sh $(RELDIR)
	@cp scripts/test_env.sh $(RELDIR)
	@tar cvzf crowdsec-release.tgz $(RELDIR)	

.PHONY:
release_static: check_release static
	@echo Building Release to dir $(RELDIR)
	@mkdir -p $(RELDIR)/cmd/crowdsec
	@mkdir -p $(RELDIR)/cmd/crowdsec-cli
	@cp $(CROWDSEC_FOLDER)/$(CROWDSEC_BIN) $(RELDIR)/cmd/crowdsec
	@cp $(CSCLI_FOLDER)/$(CSCLI_BIN) $(RELDIR)/cmd/crowdsec-cli
	@cp -R ./config/ $(RELDIR)
	@cp wizard.sh $(RELDIR)
	@cp scripts/test_env.sh $(RELDIR)
	@tar cvzf crowdsec-release-static.tgz $(RELDIR)	
