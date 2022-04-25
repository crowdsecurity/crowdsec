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

declare stderr

#----------

@test "$FILE test without -no-api flag" {
    run -124 --separate-stderr timeout 2s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
}

@test "$FILE crowdsec should not run without LAPI (-no-api flag)" {
    skip
    run -1 --separate-stderr timeout 2s "${CROWDSEC}" -no-api
}

@test "$FILE crowdsec should not run without LAPI (no api.server in configuration file)" {
    skip
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"

    run -0 echo "$stderr"
    assert_output --partial "crowdsec local API is disabled"
}

@test "$FILE capi status shouldn't be ok without api.server" {
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    run -1 --separate-stderr cscli capi status

    run -0 echo "$stderr"
    assert_output --partial "Local API is disabled, please run this command on the local API machine"
}

@test "$FILE cscli config show -o human" {
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    run -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    refute_output --partial "Local API Server:"
}

@test "$FILE cscli config backup" {
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    run -0 cscli config backup "${backupdir}"
    assert_output --partial "Starting configuration backup"
    run -1 --separate-stderr cscli config backup "${backupdir}"
    rm -rf -- "${backupdir:?}"

    run -0 echo "$stderr"
    assert_output --partial "Failed to backup configurations"
    assert_output --partial "file exists"
}

@test "$FILE lapi status shouldn't be ok without api.server" {
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    ./instance-crowdsec start || true 
    run -1 --separate-stderr cscli machines list
    run -0 echo "$stderr"
    assert_output --partial "Local API is disabled, please run this command on the local API machine"
}

@test "$FILE cscli metrics" {
    skip 'need to trigger metrics with a live parse'
    yq e 'del(.api.server)' -i "${CONFIG_YAML}"
    ./instance-crowdsec start
    run -0 --separate-stderr cscli metrics
    assert_output --partial "ROUTE"
    assert_output --partial "/v1/watchers/login"

    run -0 echo "$stderr"
    assert_output --partial "crowdsec local API is disabled"
    assert_output --partial "Local API is disabled, please run this command on the local API machine"
}
