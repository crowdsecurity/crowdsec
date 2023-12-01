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
    # always reset config and data, but run the daemon only if one test requires it
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "test without -no-api flag" {
    config_set '.common.log_media="stdout"'
    rune -0 wait-for \
        --err "CrowdSec Local API listening" \
        "${CROWDSEC}"
}

@test "crowdsec should not run without LAPI (-no-api flag)" {
    config_set '.common.log_media="stdout"'
    rune -1 wait-for "${CROWDSEC}" -no-api
}

@test "crowdsec should not run without LAPI (no api.server in configuration file)" {
    config_disable_lapi
    config_log_stderr
    rune -0 wait-for \
        --err "crowdsec local API is disabled" \
        "${CROWDSEC}"
}

@test "capi status shouldn't be ok without api.server" {
    config_disable_lapi
    rune -1 cscli capi status
    assert_stderr --partial "crowdsec local API is disabled"
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}

@test "no lapi: cscli config show -o human" {
    config_set '.api.server.enable=false'
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server (disabled):"

    config_set 'del(.api.server)'
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    refute_output --partial "Local API Server"
}

@test "cscli config backup" {
    config_disable_lapi
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    rune -0 cscli config backup "${backupdir}"
    assert_stderr --partial "Starting configuration backup"
    rune -1 cscli config backup "${backupdir}"
    rm -rf -- "${backupdir:?}"

    assert_stderr --partial "failed to backup config"
    assert_stderr --partial "file exists"
}

@test "lapi status shouldn't be ok without api.server" {
    config_disable_lapi
    ./instance-crowdsec start || true
    rune -1 cscli machines list
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}

@test "cscli metrics" {
    skip 'need to trigger metrics with a live parse'
    config_disable_lapi
    ./instance-crowdsec start
    rune -0 cscli metrics
    assert_output --partial "ROUTE"
    assert_output --partial "/v1/watchers/login"

    assert_stderr --partial "crowdsec local API is disabled"
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}
