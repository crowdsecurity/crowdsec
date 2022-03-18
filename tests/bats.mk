
# contains scripts, bats submodules, local instances and functional test suite
TEST_DIR = $(CURDIR)/tests

# contains a local instance of crowdsec, complete with configuration and data
LOCAL_DIR = $(TEST_DIR)/local

BIN_DIR = $(LOCAL_DIR)/bin
CONFIG_DIR = $(LOCAL_DIR)/etc/crowdsec
DATA_DIR = $(LOCAL_DIR)/var/lib/crowdsec/data

LOCAL_INIT_DIR = $(TEST_DIR)/local-init
LOG_DIR = $(LOCAL_DIR)/var/log
PID_DIR = $(LOCAL_DIR)/var/run
PLUGIN_DIR = $(LOCAL_DIR)/lib/crowdsec/plugins

define ENV :=
export TEST_DIR="$(TEST_DIR)"
export LOCAL_DIR="$(LOCAL_DIR)"
export CROWDSEC="$(BIN_DIR)/crowdsec"
export CSCLI="$(BIN_DIR)/cscli"
export CONFIG_YAML="$(CONFIG_DIR)/config.yaml"
export LOCAL_INIT_DIR="$(LOCAL_INIT_DIR)"
export LOG_DIR="$(LOG_DIR)"
export PID_DIR="$(PID_DIR)"
export PLUGIN_DIR="$(PLUGIN_DIR)"
endef

bats-all: bats-clean bats-build bats-test

# Source this to run the scripts outside of the Makefile
tests/.environment.sh:
	$(file >$(TEST_DIR)/.environment.sh,$(ENV))

bats-environment: tests/.environment.sh

# Verify dependencies and submodules
bats-check-requirements:
	@$(TEST_DIR)/check-requirements

# Build and installs crowdsec in a local directory
# Create a reusable package with initial configuration + data
# Generate dynamic tests
bats-build: bats-environment bats-check-requirements
	@DEFAULT_CONFIGDIR=$(CONFIG_DIR) DEFAULT_DATADIR=$(DATA_DIR) $(MAKE) build
	@mkdir -p $(BIN_DIR) $(LOG_DIR) $(PID_DIR) $(PLUGIN_DIR)
	@install -m 0755 cmd/crowdsec/crowdsec cmd/crowdsec-cli/cscli $(BIN_DIR)/
	@install -m 0755 plugins/notifications/*/notification-* $(PLUGIN_DIR)/
	@$(TEST_DIR)/instance-data make
	@$(TEST_DIR)/generate-hub-tests

# Remove the local crowdsec installation and the fixture config + data
bats-clean:
	@$(RM) -r $(LOCAL_DIR) $(LOCAL_INIT_DIR) $(TEST_DIR)/dyn-bats/*.bats tests/.environment.sh

# Run the test suite
bats-test: bats-environment bats-check-requirements
	$(TEST_DIR)/run-tests

# Static checks for the test scripts.
# Not failproof but they can catch bugs and improve learning of sh/bash
bats-lint:
	@shellcheck --version >/dev/null 2>&1 || (echo "ERROR: shellcheck is required."; exit 1)
	@shellcheck -x $(TEST_DIR)/bats/*.bats

