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
}

api() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

#----------

@test "$FILE cli - first decisions list: must be empty" {
    # delete community pull
    run -0 cscli decisions delete --all
    run -0 cscli decisions list -o json
    assert_output 'null'
}

@test "$FILE adding decision for range aaaa:2222:3333:4444::/64" {
    run -0 cscli decisions add -r 'aaaa:2222:3333:4444::/64'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE CLI - all decisions (2)" {
    run -0 cscli decisions list -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE API - all decisions (2)" {
    run -0 api '/v1/decisions'
    run -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

# check ip within/out of range

@test "$FILE CLI - decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888" {
    run -0 cscli decisions list -i 'aaaa:2222:3333:4444:5555:6666:7777:8888' -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE API - decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888" {
    run -0 api '/v1/decisions?ip=aaaa:2222:3333:4444:5555:6666:7777:8888'
    run -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE CLI - decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888" {
    run -0 cscli decisions list -i 'aaaa:2222:3333:4445:5555:6666:7777:8888' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888" {
    run -0 api '/v1/decisions?ip=aaaa:2222:3333:4445:5555:6666:7777:8888'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887" {
    run -0 cscli decisions list -i 'aaa1:2222:3333:4444:5555:6666:7777:8887' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887" {
    run -0 api '/v1/decisions?ip=aaa1:2222:3333:4444:5555:6666:7777:8887'
    assert_output 'null'
}

# check subrange within/out of range

@test "$FILE CLI - decisions for range aaaa:2222:3333:4444:5555::/80" {
    run -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555::/80' -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE API - decisions for range aaaa:2222:3333:4444:5555::/80" {
    run -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555::/80'
    run -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE CLI - decisions for range aaaa:2222:3333:4441:5555::/80" {
    run -0 cscli decisions list -r 'aaaa:2222:3333:4441:5555::/80' -o json
    assert_output 'null'

}

@test "$FILE API - decisions for range aaaa:2222:3333:4441:5555::/80" {
    run -0 api '/v1/decisions?range=aaaa:2222:3333:4441:5555::/80'
    assert_output 'null'
}

@test "$FILE CLI - decisions for range aaa1:2222:3333:4444:5555::/80" {
    run -0 cscli decisions list -r 'aaa1:2222:3333:4444:5555::/80' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range aaa1:2222:3333:4444:5555::/80" {
    run -0 api '/v1/decisions?range=aaa1:2222:3333:4444:5555::/80'
    assert_output 'null'
}

# check outer range

@test "$FILE CLI - decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 cscli decisions list -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' -o json --contained
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE API - decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 api '/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48&contains=false'
    run -0 jq -r '.[].value' <(output)
    assert_output 'aaaa:2222:3333:4444::/64'
}

@test "$FILE CLI - decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48" {
    run -0 cscli decisions list -r 'aaaa:2222:3333:4445:5555:6666:7777:8888/48' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48" {
    run -0 api '/v1/decisions?range=aaaa:2222:3333:4445:5555:6666:7777:8888/48'
    assert_output 'null'
}

# bbbb:db8:: -> bbbb:db8:0000:0000:0000:7fff:ffff:ffff

@test "$FILE adding decision for range bbbb:db8::/81" {
    run -0 cscli decisions add -r 'bbbb:db8::/81'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE CLI - decisions for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    run -0 cscli decisions list -o json -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'bbbb:db8::/81'
}

@test "$FILE API - decisions for ip in bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    run -0 api '/v1/decisions?ip=bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    run -0 jq -r '.[].value' <(output)
    assert_output 'bbbb:db8::/81'
}

@test "$FILE CLI - decisions for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    run -0 cscli decisions list -o json -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_output 'null'
}

@test "$FILE API - decisions for ip in bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    run -0 api '/v1/decisions?ip=bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_output 'null'
}

@test "$FILE deleting decision for range aaaa:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 cscli decisions delete -r 'aaaa:2222:3333:4444:5555:6666:7777:8888/48' --contained
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE CLI - decisions for range aaaa:2222:3333:4444::/64 after delete" {
    run -0 cscli decisions list -o json -r 'aaaa:2222:3333:4444::/64'
    assert_output 'null'
}

@test "$FILE adding decision for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff" {
    run -0 cscli decisions add -i 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE adding decision for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff" {
    run -0 cscli decisions add -i 'bbbb:db8:0000:0000:0000:6fff:ffff:ffff'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE deleting decisions for range bbbb:db8::/81" {
    run -0 cscli decisions delete -r 'bbbb:db8::/81' --contained
    assert_output --partial '2 decision(s) deleted'
}

@test "$FILE CLI - all decisions (3)" {
    run -0 cscli decisions list -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output 'bbbb:db8:0000:0000:0000:8fff:ffff:ffff'
}
