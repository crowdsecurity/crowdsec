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

@test "API - first decisions list: must be empty" {
    rune -0 api '/v1/decisions'
    assert_output 'null'
}

@test "adding decision for 1.2.3.4" {
    rune -0 cscli decisions add -i '1.2.3.4'
    assert_stderr --partial 'Decision successfully added'
}

@test "CLI - all decisions" {
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '1.2.3.4'
}

@test "API - all decisions" {
    rune -0 api '/v1/decisions'
    rune -0 jq -c '[ . | length, .[0].value ]' <(output)
    assert_output '[1,"1.2.3.4"]'
}

# check ip match

@test "CLI - decision for 1.2.3.4" {
    rune -0 cscli decisions list -i '1.2.3.4' -o json
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '1.2.3.4'
}

@test "API - decision for 1.2.3.4" {
    rune -0 api '/v1/decisions?ip=1.2.3.4'
    rune -0 jq -r '.[0].value' <(output)
    assert_output '1.2.3.4'
}

@test "CLI - decision for 1.2.3.5" {
    rune -0 cscli decisions list -i '1.2.3.5' -o json
    assert_output 'null'
}

@test "API - decision for 1.2.3.5" {
    rune -0 api '/v1/decisions?ip=1.2.3.5'
    assert_output 'null'
}

## check outer range match

@test "CLI - decision for 1.2.3.0/24" {
    rune -0 cscli decisions list -r '1.2.3.0/24' -o json
    assert_output 'null'
}

@test "API - decision for 1.2.3.0/24" {
    rune -0 api '/v1/decisions?range=1.2.3.0/24'
    assert_output 'null'
}

@test "CLI - decisions where IP in 1.2.3.0/24" {
    rune -0 cscli decisions list -r '1.2.3.0/24' --contained -o json
    rune -0 jq -r '.[0].decisions[0].value' <(output)
    assert_output '1.2.3.4'
}

@test "API - decisions where IP in 1.2.3.0/24" {
    rune -0 api '/v1/decisions?range=1.2.3.0/24&contains=false'
    rune -0 jq -r '.[0].value' <(output)
    assert_output '1.2.3.4'
}
