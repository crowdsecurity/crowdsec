
# contains scripts, bats submodules, local instances and functional test suite
TEST_DIR = $(CURDIR)/test

ifdef PACKAGE_TESTING
  # define PACKAGE_TESTING to test the executables already installed with
  # *.deb, *.rpm...
  LOCAL_DIR = /
  BIN_DIR = /usr/bin
  INIT_BACKEND = systemd
  CONFIG_BACKEND = global
else
  # LOCAL_DIR contains a local instance of crowdsec, complete with
  # configuration and data
  LOCAL_DIR = $(TEST_DIR)/local
  BIN_DIR = $(LOCAL_DIR)/bin
  INIT_BACKEND = daemon
  CONFIG_BACKEND = local
  PACKAGE_TESTING =
endif

CONFIG_DIR = $(LOCAL_DIR)/etc/crowdsec
DATA_DIR = $(LOCAL_DIR)/var/lib/crowdsec/data
LOCAL_INIT_DIR = $(TEST_DIR)/local-init
LOG_DIR = $(LOCAL_DIR)/var/log
PID_DIR = $(LOCAL_DIR)/var/run
# do not shadow $(PLUGINS_DIR) from the main Makefile
BATS_PLUGIN_DIR = $(LOCAL_DIR)/lib/crowdsec/plugins
DB_BACKEND ?= sqlite

CROWDSEC ?= $(BIN_DIR)/crowdsec
CSCLI ?= $(BIN_DIR)/cscli

# If you change the name of the crowdsec executable, make sure the pgrep
# parameters are correct in $(TEST_DIR)/assert-crowdsec-not-running

define ENV :=
export TEST_DIR="$(TEST_DIR)"
export LOCAL_DIR="$(LOCAL_DIR)"
export BIN_DIR="$(BIN_DIR)"
export CROWDSEC="$(CROWDSEC)"
export CSCLI="$(CSCLI)"
export CONFIG_YAML="$(CONFIG_DIR)/config.yaml"
export LOCAL_INIT_DIR="$(LOCAL_INIT_DIR)"
export LOG_DIR="$(LOG_DIR)"
export PID_DIR="$(PID_DIR)"
export PLUGIN_DIR="$(BATS_PLUGIN_DIR)"
export DB_BACKEND="$(DB_BACKEND)"
export INIT_BACKEND="$(INIT_BACKEND)"
export CONFIG_BACKEND="$(CONFIG_BACKEND)"
export PACKAGE_TESTING="$(PACKAGE_TESTING)"
export TEST_COVERAGE="$(TEST_COVERAGE)"
export GOCOVERDIR="$(TEST_DIR)/coverage"
export PATH="$(TEST_DIR)/tools:$(PATH)"
endef

bats-all: bats-clean bats-build bats-fixture bats-test bats-test-hub

# Source this to run the scripts outside of the Makefile
# Old versions of make don't have $(file) directive
bats-environment: export ENV:=$(ENV)
bats-environment:
	@echo "$${ENV}" > $(TEST_DIR)/.environment.sh

bats-check-requirements:  ## Check dependencies for functional tests
	@$(TEST_DIR)/bin/check-requirements

bats-update-tools:  ## Install/update tools required for functional tests
	# yq v4.40.4
	GOBIN=$(TEST_DIR)/tools go install github.com/mikefarah/yq/v4@1c3d55106075bd37df197b4bc03cb4a413fdb903
	# cfssl v1.6.4
	GOBIN=$(TEST_DIR)/tools go install github.com/cloudflare/cfssl/cmd/cfssl@b4d0d877cac528f63db39dfb62d5c96cd3a32a0b
	GOBIN=$(TEST_DIR)/tools go install github.com/cloudflare/cfssl/cmd/cfssljson@b4d0d877cac528f63db39dfb62d5c96cd3a32a0b

# Build and installs crowdsec in a local directory. Rebuilds if already exists.
bats-build: bats-environment  ## Build binaries for functional tests
	@$(MKDIR) $(BIN_DIR) $(LOG_DIR) $(PID_DIR) $(BATS_PLUGIN_DIR)
	@$(MAKE) build DEBUG=1 TEST_COVERAGE=$(TEST_COVERAGE) DEFAULT_CONFIGDIR=$(CONFIG_DIR) DEFAULT_DATADIR=$(DATA_DIR)
	@install -m 0755 cmd/crowdsec/crowdsec cmd/crowdsec-cli/cscli $(BIN_DIR)/
	@install -m 0755 cmd/notification-*/notification-* $(BATS_PLUGIN_DIR)/

# Create a reusable package with initial configuration + data
bats-fixture: bats-check-requirements bats-update-tools  ## Build fixture for functional tests
	@echo "Creating functional test fixture."
	@$(TEST_DIR)/instance-data make

# Remove the local crowdsec installation and the fixture config + data
# Don't remove LOCAL_DIR directly because it could be / or anything else outside the repo
bats-clean:  ## Remove functional test environment
	@$(RM) $(TEST_DIR)/local $(WIN_IGNORE_ERR)
	@$(RM) $(LOCAL_INIT_DIR) $(WIN_IGNORE_ERR)
	@$(RM) $(TEST_DIR)/dyn-bats/*.bats $(WIN_IGNORE_ERR)
	@$(RM) test/.environment.sh $(WIN_IGNORE_ERR)
	@$(RM) test/coverage/* $(WIN_IGNORE_ERR)

bats-test: bats-environment  ## Run functional tests
	$(TEST_DIR)/run-tests $(TEST_DIR)/bats

bats-test-hub: bats-environment bats-check-requirements  ## Run all hub tests
	@$(TEST_DIR)/bin/generate-hub-tests
	$(TEST_DIR)/run-tests $(TEST_DIR)/dyn-bats

# Not failproof but they can catch bugs and improve learning of sh/bash
bats-lint:  ## Static checks for the test scripts.
	@shellcheck --version >/dev/null 2>&1 || (echo "ERROR: shellcheck is required."; exit 1)
	@shellcheck -x $(TEST_DIR)/bats/*.bats

bats-test-package: bats-environment  ## CI only - test a binary package (deb, rpm, ...)
	$(TEST_DIR)/instance-data make
	$(TEST_DIR)/run-tests $(TEST_DIR)/bats
	$(TEST_DIR)/run-tests $(TEST_DIR)/dyn-bats
