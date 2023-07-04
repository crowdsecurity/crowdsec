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
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "'decisions add' requires parameters" {
    rune -1 cscli decisions add
    assert_line "Usage:"
    assert_stderr --partial "Missing arguments, a value is required (--ip, --range or --scope and --value)"

    rune -1 cscli decisions add -o json
    rune -0 jq -c '[ .level, .msg]' <(stderr | grep "^{")
    assert_output '["fatal","Missing arguments, a value is required (--ip, --range or --scope and --value)"]'
}

@test "cscli decisions list, with and without --machine" {
    is_db_postgres && skip
    rune -0 cscli decisions add -i 10.20.30.40 -t ban

    rune -0 cscli decisions list
    refute_output --partial 'Machine'
    # machine name appears quoted in the "REASON" column
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    refute_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    rune -0 cscli decisions list -m
    assert_output --partial 'Machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    rune -0 cscli decisions list --machine
    assert_output --partial 'Machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "
}

@test "cscli decisions list, incorrect parameters" {
    rune -1 cscli decisions list --until toto
    assert_stderr --partial 'Unable to list decisions : performing request: API error: while parsing duration: time: invalid duration \"toto\"'
    rune -1 cscli decisions list --until toto -o json
    rune -0 jq -c '[.level, .msg]' <(stderr | grep "^{")
    assert_output '["fatal","Unable to list decisions : performing request: API error: while parsing duration: time: invalid duration \"toto\""]'
}
