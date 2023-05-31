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

@test "adding decisions for multiple scopes" {
    rune -0 cscli decisions add -i '1.2.3.6'
    assert_stderr --partial 'Decision successfully added'
    rune -0 cscli decisions add --scope user --value toto
    assert_stderr --partial 'Decision successfully added'
}

@test "stream start (implicit ip scope)" {
    rune -0 api "/v1/decisions/stream?startup=true"
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.6'
    refute_output --partial 'toto'
}

@test "stream start (explicit ip scope)" {
    rune -0 api "/v1/decisions/stream?startup=true&scopes=ip"
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.6'
    refute_output --partial 'toto'
}

@test "stream start (user scope)" {
    rune -0 api "/v1/decisions/stream?startup=true&scopes=user"
    rune -0 jq -r '.new' <(output)
    refute_output --partial '1.2.3.6'
    assert_output --partial 'toto'
}

@test "stream start (user+ip scope)" {
    rune -0 api "/v1/decisions/stream?startup=true&scopes=user,ip"
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.6'
    assert_output --partial 'toto'
}
