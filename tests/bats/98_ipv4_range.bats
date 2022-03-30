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

#----------

api() {
    URI="$1"
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

@test "$FILE adding decision for range 4.4.4.0/24" {
    run -0 cscli decisions add -r '4.4.4.0/24'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE CLI - all decisions" {
    run -0 cscli decisions list -o json
    run -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE API - all decisions" {
    run -0 api '/v1/decisions'
    run -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

# check ip within/outside of range

@test "$FILE CLI - decisions for ip 4.4.4." {
    run -0 cscli decisions list -i '4.4.4.3' -o json
    run -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE API - decisions for ip 4.4.4." {
    run -0 api '/v1/decisions?ip=4.4.4.3'
    run -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE CLI - decisions for ip contained in 4.4.4." {
    run -0 cscli decisions list -i '4.4.4.4' -o json --contained
    assert_output 'null'
}

@test "$FILE API - decisions for ip contained in 4.4.4." {
    run -0 api '/v1/decisions?ip=4.4.4.4&contains=false'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip 5.4.4." {
    run -0 cscli decisions list -i '5.4.4.3' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for ip 5.4.4." {
    run -0 api '/v1/decisions?ip=5.4.4.3'
    assert_output 'null'
}

@test "$FILE CLI - decisions for range 4.4.0.0/1" {
    run -0 cscli decisions list -r '4.4.0.0/16' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range 4.4.0.0/1" {
    run -0 api '/v1/decisions?range=4.4.0.0/16'
    assert_output 'null'
}

@test "$FILE CLI - decisions for ip/range in 4.4.0.0/1" {
    run -0 cscli decisions list -r '4.4.0.0/16' -o json --contained
    run -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE API - decisions for ip/range in 4.4.0.0/1" {
    run -0 api '/v1/decisions?range=4.4.0.0/16&contains=false'
    run -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

# check subrange

@test "$FILE CLI - decisions for range 4.4.4.2/2" {
    run -0 cscli decisions list -r '4.4.4.2/28' -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE API - decisions for range 4.4.4.2/2" {
    run -0 api '/v1/decisions?range=4.4.4.2/28'
    run -0 jq -r '.[].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "$FILE CLI - decisions for range 4.4.3.2/2" {
    run -0 cscli decisions list -r '4.4.3.2/28' -o json
    assert_output 'null'
}

@test "$FILE API - decisions for range 4.4.3.2/2" {
    run -0 api '/v1/decisions?range=4.4.3.2/28'
    assert_output 'null'
}
