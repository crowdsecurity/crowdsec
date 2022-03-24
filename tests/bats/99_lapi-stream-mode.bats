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

@test "$FILE adding decisions for multiple ips" {
    run -0 cscli decisions add -i '1111:2222:3333:4444:5555:6666:7777:8888'
    run -0 cscli decisions add -i '1.2.3.4'
    run -0 cscli decisions add -r '1.2.4.0/24'
    assert_output --partial 'Decision successfully added'
}

@test "$FILE stream start" {
    run -0 api "/v1/decisions/stream?startup=true"
    [[ "$DB_BACKEND" == "mysql" ]] && sleep 3
    run -0 jq -r '.new' <(output)
    assert_output --partial '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_output --partial '1.2.3.4'
    assert_output --partial '1.2.4.0/24'
}

@test "$FILE stream cont (add)" {
    run -0 cscli decisions add -i '1.2.3.5'
    [[ "$DB_BACKEND" == "mysql" ]] && sleep 3
    run -0 api "/v1/decisions/stream"
    run -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.5'
}

@test "$FILE stream cont (del)" {
    run -0 cscli decisions delete -i '1.2.3.4'
    [[ "$DB_BACKEND" == "mysql" ]] && sleep 3
    run -0 api "/v1/decisions/stream"
    run -0 jq -r '.deleted' <(output)
    assert_output --partial '1.2.3.4'
}

@test "$FILE stream restart" {
    run -0 api "/v1/decisions/stream?startup=true"
    api_out=$output
    run -0 jq -r '.deleted' <(output)
    assert_output --partial '1.2.3.4'
    output=$api_out
    run -0 jq -r '.new' <(output)
    assert_output --partial '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_output --partial '1.2.3.5'
    assert_output --partial '1.2.4.0/24'
}
