#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

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

@test "without capi: crowdsec LAPI should run without capi (-no-capi flag)" {
    config_set '.common.log_media="stdout"'

    rune -0 wait-for \
        --err "Communication with CrowdSec Central API disabled from args" \
        "$CROWDSEC" -no-capi
}

@test "without capi: crowdsec LAPI should still work" {
    config_disable_capi
    config_set '.common.log_media="stdout"'
    rune -0 wait-for \
        --err "push and pull to Central API disabled" \
        "$CROWDSEC"
}

@test "without capi: cscli capi status -> fail" {
    config_disable_capi
    ./instance-crowdsec start
    rune -1 cscli capi status
    assert_stderr --partial "no configuration for Central API (CAPI) in "
}

@test "no capi: cscli config show" {
    config_disable_capi
    rune -0 cscli config show -o human
    assert_output --regexp "Global:.*Crowdsec.*cscli:.*Local API Server:"
}

@test "without capi: cscli lapi status -> success" {
    config_disable_capi
    ./instance-crowdsec start
    rune -0 cscli lapi status
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli metrics" {
    config_disable_capi
    ./instance-crowdsec start
    rune -0 cscli lapi status
    rune -0 cscli metrics
    assert_output --partial "Route"
    assert_output --partial '/v1/watchers/login'
    assert_output --partial "Local API Metrics"
}
