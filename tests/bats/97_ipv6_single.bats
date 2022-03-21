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

teardown() {
    # XXX myisam stopgap?
    sleep 0.3
}

#----------

api() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

@test "$FILE adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8888" {
    run -0 cscli decisions add -i '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE CLI - all decisions" {
    run -0 cscli decisions list -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE API - all decisions" {
    run -0 api "/v1/decisions"
    run -0 jq -r '.[].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE CLI - decisions for ip 1111:2222:3333:4444:5555:6666:7777:8888" {
    run -0 cscli decisions list -i '1111:2222:3333:4444:5555:6666:7777:8888' -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE API - decisions for ip 1111:2222:3333:4444:5555:6666:7777:888" {
    run -0 api '/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8888'
    run -0 jq -r '.[].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE CLI - decisions for ip 1211:2222:3333:4444:5555:6666:7777:8888" {
    run -0 cscli decisions list -i '1211:2222:3333:4444:5555:6666:7777:8888' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip 1211:2222:3333:4444:5555:6666:7777:888" {
    run -0 api '/v1/decisions?ip=1211:2222:3333:4444:5555:6666:7777:8888'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip 1111:2222:3333:4444:5555:6666:7777:8887" {
    run -0 cscli decisions list -i '1111:2222:3333:4444:5555:6666:7777:8887' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip 1111:2222:3333:4444:5555:6666:7777:8887" {
    run -0 api '/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8887'
    assert_output 'null'
}

@test "$FILE CLI - decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 cscli decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/48' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 api '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 cscli decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/48' --contained -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE API - decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/48" {
    run -0 api '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48&&contains=false'
    run -0 jq -r '.[].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE CLI - decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run -0 cscli decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run -0 api '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run -0 cscli decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json --contained
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE API - decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run -0 api '/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64&&contains=false'
    run -0 jq -r '.[].value' <(output)
    assert_output '1111:2222:3333:4444:5555:6666:7777:8888'
}

@test "$FILE adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8889" {
    run -0 cscli decisions add -i '1111:2222:3333:4444:5555:6666:7777:8889'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE deleting decision for ip 1111:2222:3333:4444:5555:6666:7777:8889" {
    run -0 cscli decisions delete -i '1111:2222:3333:4444:5555:6666:7777:8889'
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE CLI - decisions for ip 1111:2222:3333:4444:5555:6666:7777:8889 after delete" {
    run -0 cscli decisions list -i '1111:2222:3333:4444:5555:6666:7777:8889' -o json
    assert_output 'null'
}

@test "$FILE deleting decision for range 1111:2222:3333:4444:5555:6666:7777:8888/64" {
    run -0 cscli decisions delete -r '1111:2222:3333:4444:5555:6666:7777:8888/64' --contained
    assert_output --partial '1 decision(s) deleted'
}

@test "$FILE CLI - decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64 after delete" {
    run -0 cscli decisions list -r '1111:2222:3333:4444:5555:6666:7777:8888/64' -o json --contained
    assert_output 'null'
}
