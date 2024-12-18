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
    assert_stderr --partial "unable to delete bouncer something: ent: bouncer not found"
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
    rune -1 cscli bouncers add ciTestBouncer

    assert_stderr 'Error: unable to create bouncer: bouncer ciTestBouncer already exists'

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

curl_localhost() {
    [[ -z "$API_KEY" ]] && { fail "${FUNCNAME[0]}: missing API_KEY"; }
    local path=$1
    shift
    curl "localhost:8080$path" -sS --fail-with-body -H "X-Api-Key: $API_KEY" "$@"
}

# We can't use curl-with-key here, as we want to query localhost, not 127.0.0.1
@test "multiple bouncers sharing api key" {
    export API_KEY=bouncerkey

    # crowdsec needs to listen on all interfaces
    rune -0 ./instance-crowdsec stop
    rune -0 config_set 'del(.api.server.listen_socket) | del(.api.server.listen_uri)'
    echo "{'api':{'server':{'listen_uri':0.0.0.0:8080}}}" >"${CONFIG_YAML}.local"

    rune -0 ./instance-crowdsec start

    # add a decision for our bouncers
    rune -0 cscli decisions add -i '1.2.3.5'

    rune -0 cscli bouncers add test-auto -k "$API_KEY"

    # query with 127.0.0.1 as source ip
    rune -0 curl_localhost "/v1/decisions/stream" -4
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.5'

    # now with ::1, we should get the same IP, even though we are using the same key
    rune -0 curl_localhost "/v1/decisions/stream" -6
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.5'

    rune -0 cscli bouncers list -o json
    rune -0 jq -c '[.[] | [.name,.revoked,.ip_address,.auto_created]]' <(output)
    assert_json '[["test-auto",false,"127.0.0.1",false],["test-auto@::1",false,"::1",true]]'

    # check the 2nd bouncer was created automatically
    rune -0 cscli bouncers inspect "test-auto@::1" -o json
    rune -0 jq -r '.ip_address' <(output)
    assert_output --partial '::1'

    # attempt to delete the auto-created bouncer, it should fail
    rune -0 cscli bouncers delete 'test-auto@::1'
    assert_stderr --partial 'cannot be deleted'

    # delete the "real" bouncer, it should delete both
    rune -0 cscli bouncers delete 'test-auto'

    rune -0 cscli bouncers list -o json
    assert_json []
}
