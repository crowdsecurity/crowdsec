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

@test "adding decision for range 4.4.4.0/24" {
    rune -0 cscli decisions add -r '4.4.4.0/24'
    assert_stderr --partial 'Decision successfully added'
}

@test "CLI - all decisions" {
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "API - all decisions" {
    rune -0 api '/v1/decisions'
    rune -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

# check ip within/outside of range

@test "CLI - decisions for ip 4.4.4." {
    rune -0 cscli decisions list -i '4.4.4.3' -o json
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "API - decisions for ip 4.4.4." {
    rune -0 api '/v1/decisions?ip=4.4.4.3'
    rune -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "CLI - decisions for ip contained in 4.4.4." {
    rune -0 cscli decisions list -i '4.4.4.4' -o json --contained
    assert_output 'null'
}

@test "API - decisions for ip contained in 4.4.4." {
    rune -0 api '/v1/decisions?ip=4.4.4.4&contains=false'
    assert_output 'null'
}

@test "CLI - decisions for ip 5.4.4." {
    rune -0 cscli decisions list -i '5.4.4.3' -o json
    assert_output 'null'
}

@test "API - decisions for ip 5.4.4." {
    rune -0 api '/v1/decisions?ip=5.4.4.3'
    assert_output 'null'
}

@test "CLI - decisions for range 4.4.0.0/1" {
    rune -0 cscli decisions list -r '4.4.0.0/16' -o json
    assert_output 'null'
}

@test "API - decisions for range 4.4.0.0/1" {
    rune -0 api '/v1/decisions?range=4.4.0.0/16'
    assert_output 'null'
}

@test "CLI - decisions for ip/range in 4.4.0.0/1" {
    rune -0 cscli decisions list -r '4.4.0.0/16' -o json --contained
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "API - decisions for ip/range in 4.4.0.0/1" {
    rune -0 api '/v1/decisions?range=4.4.0.0/16&contains=false'
    rune -0 jq -r '.[0].value' <(output)
    assert_output '4.4.4.0/24'
}

# check subrange

@test "CLI - decisions for range 4.4.4.2/2" {
    rune -0 cscli decisions list -r '4.4.4.2/28' -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "API - decisions for range 4.4.4.2/2" {
    rune -0 api '/v1/decisions?range=4.4.4.2/28'
    rune -0 jq -r '.[].value' <(output)
    assert_output '4.4.4.0/24'
}

@test "CLI - decisions for range 4.4.3.2/2" {
    rune -0 cscli decisions list -r '4.4.3.2/28' -o json
    assert_output 'null'
}

@test "API - decisions for range 4.4.3.2/2" {
    rune -0 api '/v1/decisions?range=4.4.3.2/28'
    assert_output 'null'
}
