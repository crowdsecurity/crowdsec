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
    assert_json '[]'

    rune -0 cscli bouncers list -o human
    assert_output --partial "Name"

    rune -0 cscli bouncers list -o raw
    assert_output --partial 'name'
}

@test "we can add one bouncer, and delete it" {
    rune -0 cscli bouncers add ciTestBouncer
    assert_output --partial "API key for 'ciTestBouncer':"
    rune -0 cscli bouncers delete ciTestBouncer
    rune -0 cscli bouncers list -o json
    assert_json '[]'
}

@test "bouncer api-key auth" {
    rune -0 cscli bouncers add ciTestBouncer --key "goodkey"

    # connect with good credentials
    rune -0 curl-tcp "/v1/decisions" -sS --fail-with-body -H "X-Api-Key: goodkey"
    assert_output null

    # connect with bad credentials
    rune -22 curl-tcp "/v1/decisions" -sS --fail-with-body -H "X-Api-Key: badkey"
    assert_stderr --partial 'error: 403'
    assert_json '{message:"access forbidden"}'

    # connect with no credentials
    rune -22 curl-tcp "/v1/decisions" -sS --fail-with-body
    assert_stderr --partial 'error: 403'
    assert_json '{message:"access forbidden"}'
}

@test "delete non-existent bouncer" {
    # this is a fatal error, which is not consistent with "machines delete"
    rune -1 cscli bouncers delete something
    assert_stderr --partial "unable to delete bouncer: 'something' does not exist"
    rune -0 cscli bouncers delete something --ignore-missing
    refute_stderr
}

@test "bouncers delete has autocompletion" {
    rune -0 cscli bouncers add foo1
    rune -0 cscli bouncers add foo2
    rune -0 cscli bouncers add bar
    rune -0 cscli bouncers add baz
    rune -0 cscli __complete bouncers delete 'foo'
    assert_line --index 0 'foo1'
    assert_line --index 1 'foo2'
    refute_line 'bar'
    refute_line 'baz'
}

@test "cscli bouncers list" {
    export API_KEY=bouncerkey
    rune -0 cscli bouncers add ciTestBouncer --key "$API_KEY"

    rune -0 cscli bouncers list -o json
    rune -0 jq -c '.[] | [.ip_address,.last_pull,.name]' <(output)
    assert_json '["",null,"ciTestBouncer"]'
    rune -0 cscli bouncers list -o raw
    assert_line 'name,ip,revoked,last_pull,type,version,auth_type'
    assert_line 'ciTestBouncer,,validated,,,,api-key'
    rune -0 cscli bouncers list -o human
    assert_output --regexp 'ciTestBouncer.*api-key.*'

    # the first connection sets last_pull and ip address
    rune -0 curl-with-key '/v1/decisions'
    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[] | .ip_address' <(output)
    assert_output 127.0.0.1
    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[] | .last_pull' <(output)
    refute_output null
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

@test "cscli bouncers prune" {
    rune -0 cscli bouncers prune
    assert_output 'No bouncers to prune.'
    rune -0 cscli bouncers add ciTestBouncer

    rune -0 cscli bouncers prune
    assert_output 'No bouncers to prune.'
}
