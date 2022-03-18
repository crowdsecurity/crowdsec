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

@test "$FILE cscli alerts list, with and without --machine" {
    run -0 cscli decisions add -i 10.20.30.40 -t ban

    run -0 cscli alerts list
    refute_output --partial 'MACHINE'
    # machine name appears quoted in the "REASON" column
    assert_output --partial "| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX' |"
    refute_output --partial "| githubciXXXXXXXXXXXXXXXXXXXXXXXX |"

    run -0 cscli alerts list -m
    assert_output --partial 'MACHINE'
    assert_output --partial "| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX' |"
    assert_output --partial "| githubciXXXXXXXXXXXXXXXXXXXXXXXX |"

    run -0 cscli alerts list --machine
    assert_output --partial 'MACHINE'
    assert_output --partial "| 'githubciXXXXXXXXXXXXXXXXXXXXXXXX' |"
    assert_output --partial "| githubciXXXXXXXXXXXXXXXXXXXXXXXX |"
}
