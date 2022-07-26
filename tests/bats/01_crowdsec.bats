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

@test "crowdsec (usage)" {
    run -0 --separate-stderr timeout 2s "${CROWDSEC}" -h
    run -0 echo "${stderr}"
    assert_line --regexp "Usage of .*:"

    run -0 --separate-stderr timeout 2s "${CROWDSEC}" --help
    run -0 echo "${stderr}"
    assert_line --regexp "Usage of .*:"
}

@test "crowdsec (unknown flag)" {
    run -2 --separate-stderr timeout 2s "${CROWDSEC}" --foobar
    run -0 echo "${stderr}"
    assert_line "flag provided but not defined: -foobar"
    assert_line --regexp "Usage of .*"
}

@test "crowdsec (unknown argument)" {
    run -2 --separate-stderr timeout 2s "${CROWDSEC}" trololo
    run -0 echo "${stderr}"
    assert_line "argument provided but not defined: trololo"
    assert_line --regexp "Usage of .*"
}

@test "crowdsec (no api and no agent)" {
    run -1 --separate-stderr timeout 2s "${CROWDSEC}" -no-api -no-cs
    run -0 echo "${stderr}"
    assert_line --partial "You must run at least the API Server or crowdsec"
}

@test "crowdsec - print error on exit" {
    # errors that cause program termination are printed to stderr, not only logs
    config_set '.db_config.type="meh"'
    run -1 --separate-stderr "${BIN_DIR}/crowdsec"
    refute_output
    run -0 echo "${stderr}"
    assert_output --partial "unable to create database client: unknown database type 'meh'"
}

@test "CS_LAPI_SECRET not strong enough" {
    CS_LAPI_SECRET=foo run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: controller init: CS_LAPI_SECRET not strong enough"
}
