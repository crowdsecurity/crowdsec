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

declare stderr

#----------

@test "$FILE 'decisions add' requires parameters" {
    run -1 --separate-stderr cscli decisions add
    assert_line "Usage:"
    run echo "$stderr"
    assert_output --partial "Missing arguments, a value is required (--ip, --range or --scope and --value)"

    run -1 --separate-stderr cscli decisions add -o json
    run echo "$stderr"
    run -0 jq -c '[ .level, .msg]' <(output)
    assert_output '["fatal","Missing arguments, a value is required (--ip, --range or --scope and --value)"]'
}

@test "$FILE cscli decisions list, with and without --machine" {
    run -0 cscli decisions add -i 10.20.30.40 -t ban

    run -0 cscli decisions list
    refute_output --partial 'MACHINE'
    # machine name appears quoted in the "REASON" column
    assert_output --regexp "\| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' \|"
    refute_output --regexp "\| githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? \|"

    run -0 cscli decisions list -m
    assert_output --partial 'MACHINE'
    assert_output --regexp "\| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' \|"
    assert_output --regexp "\| githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? \|"

    run -0 cscli decisions list --machine
    assert_output --partial 'MACHINE'
    assert_output --regexp "\| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' \|"
    assert_output --regexp "\| githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? \|"
}
