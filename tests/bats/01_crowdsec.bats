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
