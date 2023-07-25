#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    ./instance-crowdsec start
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY
    CROWDSEC_API_URL="http://localhost:8080"
    export CROWDSEC_API_URL
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    if is_db_mysql; then sleep 0.3; fi
}

api() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

#----------

@test "cli - first decisions list: must be empty" {
    # delete community pull
    rune -0 cscli decisions delete --all
    rune -0 cscli decisions list -o json
    assert_output 'null'
}

@test "adding decision for range aaaa:2222:3333:4444::/64" {
    rune -0 cscli decisions add -r 'aaaa:2222:3333:4444::/64'
    assert_stderr --partial 'Decision successfully added'
}

@test "CLI - all decisions (2)" {
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "API - all decisions (2)" {
    rune -0 api '/v1/decisions'
    rune -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

# check ip within/out of range

@test "CLI - decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888" {
    rune -0 cscli decisions list -i 'aaaa:2222:3333:4444:5555:6666:7777:8888' -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "API - decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888" {
    rune -0 api '/v1/decisions?ip=aaaa:2222:3333:4444:5555:6666:7777:8888'
    rune -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "CLI - decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888" {
    rune -0 cscli decisions list -i 'aaaa:2222:3333:4445:5555:6666:7777:8888' -o json
    assert_output 'null'
}

@test "API - decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888" {
    rune -0 api '/v1/decisions?ip=aaaa:2222:3333:4445:5555:6666:7777:8888'
    assert_output 'null'
}

@test "CLI - decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887" {
    rune -0 cscli decisions list -i 'aaa1:2222:3333:4444:5555:6666:7777:8887' -o json
    assert_output 'null'
}

@test "API - decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887" {
    rune -0 api '/v1/decisions?ip=aaa1:2222:3333:4444:5555:6666:7777:8887'
    assert_output 'null'
}

# check subrange within/out of range

@test "CLI - decisions for range aaaa:2222:3333:4444:5555::/80" {
    rune -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555::/80' -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "API - decisions for range aaaa:2222:3333:4444:5555::/80" {
    rune -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555::/80'
    rune -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "CLI - decisions for range aaaa:2222:3333:4441:5555::/80" {
    rune -0 cscli decisions list -r 'aaaa:2222:3333:4441:5555::/80' -o json
    assert_output 'null'

}

@test "API - decisions for range aaaa:2222:3333:4441:5555::/80" {
    rune -0 api '/v1/decisions?range=aaaa:2222:3333:4441:5555::/80'
    assert_output 'null'
}

@test "CLI - decisions for range aaa1:2222:3333:4444:5555::/80" {
    rune -0 cscli decisions list -r 'aaa1:2222:3333:4444:5555::/80' -o json
    assert_output 'null'
}

@test "API - decisions for range aaa1:2222:3333:4444:5555::/80" {
    rune -0 api '/v1/decisions?range=aaa1:2222:3333:4444:5555::/80'
    assert_output 'null'
}

# check outer range

@test "CLI - decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    rune -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json
    assert_output 'null'
}

@test "API - decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    rune -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48'
    assert_output 'null'
}

@test "CLI - decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    rune -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json --contained
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "API - decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    rune -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48&contains=false'
    rune -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "CLI - decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48" {
    rune -0 cscli decisions list -r 'aaaa:2222:3333:4445:5555:6666:7777:8888/48' -o json
    assert_output 'null'
}

@test "API - decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48" {
    rune -0 api '/v1/decisions?range=aaaa:2222:3333:4445:5555:6666:7777:8888/48'
    assert_output 'null'
}

# bbbb:db8:: -> bbbb:db8:0000:0000:0000:7fff:ffff:ffff

@test "adding decision for range bbbb:db8::/81" {
    rune -0 cscli decisions add -r 'bbbb:db8::/81'
    assert_stderr --partial 'Decision successfully added'
}

@test "CLI - decisions for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    rune -0 cscli decisions list -o json -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'bbbb:db8::/81'
}

@test "API - decisions for ip in bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    rune -0 api '/v1/decisions?ip=bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    rune -0 jq -r '.[].value' <(output)
    assert_output 'bbbb:db8::/81'
}

@test "CLI - decisions for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    rune -0 cscli decisions list -o json -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_output 'null'
}

@test "API - decisions for ip in bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    rune -0 api '/v1/decisions?ip=bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_output 'null'
}

@test "deleting decision for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    rune -0 cscli decisions delete -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' --contained
    assert_stderr --partial '1 decision(s) deleted'
}

@test "CLI - decisions for range aaaa:2222:3333:4444::/64 after delete" {
    rune -0 cscli decisions list -o json -r 'aaaa:2222:3333:4444::/64'
    assert_output 'null'
}

@test "adding decision for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    rune -0 cscli decisions add -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_stderr --partial 'Decision successfully added'
}

@test "adding decision for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    rune -0 cscli decisions add -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    assert_stderr --partial 'Decision successfully added'
}

@test "deleting decisions for range bbbb:db8::/81" {
    rune -0 cscli decisions delete -r 'bbbb:db8::/81' --contained
    assert_stderr --partial '2 decision(s) deleted'
}

@test "CLI - all decisions (3)" {
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
}
