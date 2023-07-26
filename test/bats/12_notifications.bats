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
    load "../lib/bats-file/load.bash"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    cd "$TEST_DIR" || exit 1
    ./instance-crowdsec stop
}

#----------

@test "cscli notifications list" {
    rune -0 cscli notifications list
    assert_output --partial "Name"
    assert_output --partial "Type"
    assert_output --partial "Profile name"
}

@test "cscli notifications must be run from lapi" {
    config_disable_lapi
    rune -1 cscli notifications list
    assert_stderr --partial "local API is disabled, please run this command on the local API machine"
}
