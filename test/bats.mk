
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
  # LOCAL_DIR will contain contains a local instance of crowdsec, complete with
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
PLUGIN_DIR = $(LOCAL_DIR)/lib/crowdsec/plugins
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
export PLUGIN_DIR="$(PLUGIN_DIR)"
export DB_BACKEND="$(DB_BACKEND)"
export INIT_BACKEND="$(INIT_BACKEND)"
export CONFIG_BACKEND="$(CONFIG_BACKEND)"
export PACKAGE_TESTING="$(PACKAGE_TESTING)"
export TEST_COVERAGE="$(TEST_COVERAGE)"
export GOCOVERDIR="$(TEST_DIR)/coverage"
endef

bats-all: bats-clean bats-build bats-fixture bats-test bats-test-hub

# Source this to run the scripts outside of the Makefile
# Old versions of make don't have $(file) directive
bats-environment: export ENV:=$(ENV)
bats-environment:
	@echo "$${ENV}" > $(TEST_DIR)/.environment.sh

# Verify dependencies and submodules
bats-check-requirements:
	@$(TEST_DIR)/bin/check-requirements

# Build and installs crowdsec in a local directory. Rebuilds if already exists.
bats-build: bats-environment bats-check-requirements
	@mkdir -p $(BIN_DIR) $(LOG_DIR) $(PID_DIR) $(PLUGIN_DIR)
	@TEST_COVERAGE=$(TEST_COVERAGE) DEFAULT_CONFIGDIR=$(CONFIG_DIR) DEFAULT_DATADIR=$(DATA_DIR) $(MAKE) goversion crowdsec cscli plugins
	@install -m 0755 cmd/crowdsec/crowdsec cmd/crowdsec-cli/cscli $(BIN_DIR)/
	@install -m 0755 plugins/notifications/*/notification-* $(PLUGIN_DIR)/

# Create a reusable package with initial configuration + data
bats-fixture:
	@$(TEST_DIR)/instance-data make

# Remove the local crowdsec installation and the fixture config + data
# Don't remove LOCAL_DIR directly because it could be / or anything else outside the repo
bats-clean:
	@$(RM) $(TEST_DIR)/local $(WIN_IGNORE_ERR)
	@$(RM) $(LOCAL_INIT_DIR) $(WIN_IGNORE_ERR)
	@$(RM) $(TEST_DIR)/dyn-bats/*.bats $(WIN_IGNORE_ERR)
	@$(RM) test/.environment.sh $(WIN_IGNORE_ERR)
	@$(RM) test/coverage/* $(WIN_IGNORE_ERR)

# Run the test suite
bats-test: bats-environment bats-check-requirements
	$(TEST_DIR)/run-tests $(TEST_DIR)/bats

# Generate dynamic tests
bats-test-hub: bats-environment bats-check-requirements
	@$(TEST_DIR)/bin/generate-hub-tests
	$(TEST_DIR)/run-tests $(TEST_DIR)/dyn-bats

# Static checks for the test scripts.
# Not failproof but they can catch bugs and improve learning of sh/bash
bats-lint:
	@shellcheck --version >/dev/null 2>&1 || (echo "ERROR: shellcheck is required."; exit 1)
	@shellcheck -x $(TEST_DIR)/bats/*.bats


bats-test-package: bats-environment
	$(TEST_DIR)/instance-data make
	$(TEST_DIR)/run-tests $(TEST_DIR)/bats
	$(TEST_DIR)/run-tests $(TEST_DIR)/dyn-bats

.PHONY: bats-environment
