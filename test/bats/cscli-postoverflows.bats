#!/usr/bin/env bats

# Tests for the "cscli postoverflows" behavior that is not covered by cscli-hubtype-*.bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
    INDEX_PATH=$(config_get '.config_paths.index_path')
    export INDEX_PATH
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    export CONFIG_DIR
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli postoverflows inspect (includes the stage attribute)" {
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics -o human
    assert_line 'stage: s00-enrich'

    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics -o raw
    assert_line 'stage: s00-enrich'

    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics -o json
    rune -0 jq -r '.stage' <(output)
    assert_output 's00-enrich'
}
