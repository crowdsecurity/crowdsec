#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "misconfigured scenario" {
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    mkdir -p "$CONFIG_DIR/scenarios/local"
    echo "name: foo" >"$CONFIG_DIR/scenarios/local/foo.yaml"
    config_set '.common.log_media="stdout"'
    rune -1 "$CROWDSEC"
    # XXX:
    assert_stderr --partial "Bucket without filter, abort."
    assert_stderr --partial "crowdsec init: while loading scenarios: bucket foo: missing filter directive"
    refute_output
}
