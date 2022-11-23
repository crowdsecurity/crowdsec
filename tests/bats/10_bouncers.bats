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

@test "there are 0 bouncers" {
    run -0 --separate-stderr cscli bouncers list -o json
    assert_output "[]"
}

@test "we can add one bouncer, and delete it" {
    run -0 cscli bouncers add ciTestBouncer
    assert_output --partial "Api key for 'ciTestBouncer':"
    run -0 cscli bouncers delete ciTestBouncer
    run -0 --separate-stderr cscli bouncers list -o json
    assert_output '[]'
}

@test "we can't add the same bouncer twice" {
    run -0 cscli bouncers add ciTestBouncer
    run -1 --separate-stderr cscli bouncers add ciTestBouncer -o json

    run -0 jq -r '.level' <(stderr)
    assert_output 'fatal'
    run -0 jq -r '.msg' <(stderr)
    assert_output "unable to create bouncer: bouncer ciTestBouncer already exists"

    run -0 cscli bouncers list -o json
    run -0 jq '. | length' <(output)
    assert_output 1
}

@test "delete the bouncer multiple times, even if it does not exist" {
    run -0 cscli bouncers add ciTestBouncer
    run -0 cscli bouncers delete ciTestBouncer
    run -1 cscli bouncers delete ciTestBouncer
    run -1 cscli bouncers delete foobarbaz
}
