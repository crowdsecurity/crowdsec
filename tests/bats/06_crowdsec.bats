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

# to silence shellcheck
declare stderr

#----------

@test "${FILE} crowdsec - print error on exit" {
    # errors that cause program termination are printed to stderr, not only logs
    yq e '.db_config.type="meh"' -i "${CONFIG_YAML}"
    run -1 --separate-stderr "${BIN_DIR}/crowdsec"
    refute_output
    run -0 echo "${stderr}"
    assert_output --partial "unable to create database client: unknown database type 'meh'"
}

@test "${FILE} CS_LAPI_SECRET not strong enough" {
    CS_LAPI_SECRET=foo run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: controller init: CS_LAPI_SECRET not strong enough"
}
