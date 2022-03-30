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

declare stderr

#----------

config_disable_agent() {
    yq 'del(.crowdsec_service)' -i "${CONFIG_YAML}"
}

@test "$FILE with agent: test without -no-cs flag" {
    run -124 timeout 2s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
}

@test "$FILE no agent: crowdsec LAPI should run (-no-cs flag)" {
    run -124 timeout 2s "${CROWDSEC}" -no-cs
}

@test "$FILE no agent: crowdsec LAPI should run (no crowdsec_service in configuration file)" {
    config_disable_agent
    run -124 --separate-stderr timeout 2s "${CROWDSEC}"

    run -0 echo "$stderr"
    assert_output --partial "crowdsec agent is disabled"
}

@test "$FILE no agent: capi status should be ok" {
    config_disable_agent
    ./instance-crowdsec start
    run -0 --separate-stderr cscli capi status

    run -0 echo "$stderr"
    assert_output --partial "You can successfully interact with Central API (CAPI)"
}

@test "$FILE no agent: cscli config show" {
    config_disable_agent
    run -0 --separate-stderr cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"

    refute_output --partial "Crowdsec:"
}

@test "$FILE no agent: cscli config backup" {
    config_disable_agent
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    run -0 cscli config backup "${backupdir}"
    assert_output --partial "Starting configuration backup"
    run -1 --separate-stderr cscli config backup "${backupdir}"

    run -0 echo "$stderr"
    assert_output --partial "Failed to backup configurations"
    assert_output --partial "file exists"
    rm -rf -- "${backupdir:?}"
}

@test "$FILE no agent: lapi status should be ok" {
    config_disable_agent
    ./instance-crowdsec start
    run -0 --separate-stderr cscli lapi status

    run -0 echo "$stderr"
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "$FILE cscli metrics" {
    config_disable_agent
    ./instance-crowdsec start
    run -0 cscli lapi status
    run -0 cscli metrics
}
