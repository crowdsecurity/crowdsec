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

    run -124 --separate-stderr timeout 1s "${CROWDSEC}" -no-capi
    assert_stderr --partial "Communication with CrowdSec Central API disabled from args"
}

@test "without capi: crowdsec LAPI should still work" {
    config_disable_capi
    run -124 --separate-stderr timeout 1s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
    assert_stderr --partial "push and pull to Central API disabled"
}

@test "without capi: cscli capi status -> fail" {
    config_disable_capi
    ./instance-crowdsec start
    run -1 --separate-stderr cscli capi status
    assert_stderr --partial "no configuration for Central API in "
}

@test "no capi: cscli config show" {
    config_disable_capi
    run -0 --separate-stderr cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "Local API Server:"
}

@test "no agent: cscli config backup" {
    config_disable_capi
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    run -0 cscli config backup "${backupdir}"
    assert_output --partial "Starting configuration backup"
    run -1 --separate-stderr cscli config backup "${backupdir}"
    assert_stderr --partial "Failed to backup configurations"
    assert_stderr --partial "file exists"
    rm -rf -- "${backupdir:?}"
}

@test "without capi: cscli lapi status -> success" {
    config_disable_capi
    ./instance-crowdsec start
    run -0 --separate-stderr cscli lapi status
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli metrics" {
    config_disable_capi
    ./instance-crowdsec start
    run -0 cscli lapi status
    run -0 --separate-stderr cscli metrics
    assert_output --partial "ROUTE"
    assert_output --partial '/v1/watchers/login'
    assert_output --partial "Local Api Metrics:"

}
