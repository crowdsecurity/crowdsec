PREFIX?="/tmp/crowdsec/"
CFG_PREFIX = $(PREFIX)"/etc/crowdsec/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"
DATA_PREFIX = $(PREFIX)"/var/run/crowdsec/"

PLUGIN_FOLDER="./plugins"
PID_DIR = $(PREFIX)"/var/run/"
CROWDSEC_FOLDER = "./cmd/crowdsec"
CSCLI_FOLDER = "./cmd/crowdsec-cli/"
CROWDSEC_BIN = "crowdsec"
CSCLI_BIN = "cscli"
BUILD_CMD="build"

GOARCH=amd64
GOOS=linux
REQUIRE_GOVERSION="1.13"


#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags `git rev-list --tags --max-count=1`)"
BUILD_GOVERSION="$(shell go version | cut -d " " -f3 | sed -r 's/[go]+//g')"
BUILD_CODENAME=$(shell cat RELEASE.json | jq -r .CodeName)
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"
export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME)  \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.GoVersion=$(BUILD_GOVERSION)"
RELDIR = crowdsec-$(BUILD_VERSION)

all: clean test build

build: clean goversion crowdsec cscli

static: goversion crowdsec_static cscli_static

goversion:
	CURRENT_GOVERSION="$(shell go version | cut -d " " -f3 | sed -r 's/[go]+//g')"
	RESPECT_VERSION="$(shell echo "$(CURRENT_GOVERSION),$(REQUIRE_GOVERSION)" | tr ',' '\n' | sort -V)"


hubci:
	@rm -rf crowdsec-xxx hub-tests
	BUILD_VERSION=xxx make release
	@git clone https://github.com/crowdsecurity/hub-tests.git
	@cd hub-tests && make
	@cd crowdsec-xxx && ./test_env.sh
	@cd crowdsec-xxx/tests && bash ../../scripts/install_all.sh
	@cp hub-tests/main ./crowdsec-xxx/tests/
	@cp -R hub-tests/tests ./crowdsec-xxx/tests/
	@cd ./crowdsec-xxx/tests/ && bash ../../hub-tests/run_tests.sh

clean:
	@make -C $(CROWDSEC_FOLDER) clean --no-print-directory
	@make -C $(CSCLI_FOLDER) clean --no-print-directory
	@rm -f $(CROWDSEC_BIN)
	@rm -f $(CSCLI_BIN)
	@rm -f *.log

cscli:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@make -C $(CSCLI_FOLDER) build --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


crowdsec:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@make -C $(CROWDSEC_FOLDER) build --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif
	@bash ./scripts/build_plugins.sh


cscli_static:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@make -C $(CSCLI_FOLDER) static --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


crowdsec_static:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@make -C $(CROWDSEC_FOLDER) static --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif


#.PHONY: test
test:
ifeq ($(lastword $(RESPECT_VERSION)), $(CURRENT_GOVERSION))
	@make -C $(CROWDSEC_FOLDER) test --no-print-directory
else
	@echo "Required golang version is $(REQUIRE_GOVERSION). The current one is $(CURRENT_GOVERSION). Exiting.."
	@exit 1;
endif

.PHONY: uninstall
uninstall:
	@rm -rf "$(CFG_PREFIX)" || exit
	@rm -rf "$(DATA_PREFIX)" || exit
	@rm -rf "$(SYSTEMD_PATH_FILE)" || exit

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
	@bash ./scripts/build_plugins.sh
	@mkdir -p "$(RELDIR)/plugins/backend"
	@find ./plugins -type f -name "*.so" -exec install -Dm 644 {} "$(RELDIR)/{}" \; || exiting 
	@tar cvzf crowdsec-release.tgz $(RELDIR)	
