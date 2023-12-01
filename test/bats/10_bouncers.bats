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
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "we can add one bouncer, and delete it" {
    rune -0 cscli bouncers add ciTestBouncer
    assert_output --partial "API key for 'ciTestBouncer':"
    rune -0 cscli bouncers delete ciTestBouncer
    rune -0 cscli bouncers list -o json
    assert_output '[]'
}

@test "we can create a bouncer with a known key" {
    # also test the output formats since we know the key
    rune -0 cscli bouncers add ciTestBouncer --key "foobarbaz" -o human
    assert_output --partial 'foobarbaz'
    rune -0 cscli bouncers delete ciTestBouncer
    rune -0 cscli bouncers add ciTestBouncer --key "foobarbaz" -o json
    assert_output '"foobarbaz"'
    rune -0 cscli bouncers delete ciTestBouncer
    rune -0 cscli bouncers add ciTestBouncer --key "foobarbaz" -o raw
    assert_output foobarbaz
}

@test "we can't add the same bouncer twice" {
    rune -0 cscli bouncers add ciTestBouncer
    rune -1 cscli bouncers add ciTestBouncer -o json

    # XXX temporary hack to filter out unwanted log lines that may appear before
    # log configuration (= not json)
    rune -0 jq -c '[.level,.msg]' <(stderr | grep "^{")
    assert_output '["fatal","unable to create bouncer: bouncer ciTestBouncer already exists"]'

    rune -0 cscli bouncers list -o json
    rune -0 jq '. | length' <(output)
    assert_output 1
}

@test "delete the bouncer multiple times, even if it does not exist" {
    rune -0 cscli bouncers add ciTestBouncer
    rune -0 cscli bouncers delete ciTestBouncer
    rune -1 cscli bouncers delete ciTestBouncer
    rune -1 cscli bouncers delete foobarbaz
}
