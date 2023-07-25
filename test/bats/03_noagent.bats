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

@test "with agent: test without -no-cs flag" {
    rune -124 timeout 2s "${CROWDSEC}"
    # from `man timeout`: If  the  command  times  out,  and --preserve-status is not set, then exit with status 124.
}

@test "no agent: crowdsec LAPI should run (-no-cs flag)" {
    rune -124 timeout 2s "${CROWDSEC}" -no-cs
}

@test "no agent: crowdsec LAPI should run (no crowdsec_service in configuration file)" {
    config_disable_agent
    config_log_stderr
    rune -124 timeout 2s "${CROWDSEC}"

    assert_stderr --partial "crowdsec agent is disabled"
}

@test "no agent: cscli config show" {
    config_disable_agent
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"

    refute_output --partial "Crowdsec:"
}

@test "no agent: cscli config backup" {
    config_disable_agent
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    rune -0 cscli config backup "${backupdir}"
    assert_stderr --partial "Starting configuration backup"
    rune -1 cscli config backup "${backupdir}"

    assert_stderr --partial "failed to backup config"
    assert_stderr --partial "file exists"
    rm -rf -- "${backupdir:?}"
}

@test "no agent: lapi status should be ok" {
    config_disable_agent
    ./instance-crowdsec start
    rune -0 cscli lapi status
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli metrics" {
    config_disable_agent
    ./instance-crowdsec start
    rune -0 cscli lapi status
    rune -0 cscli metrics
}
