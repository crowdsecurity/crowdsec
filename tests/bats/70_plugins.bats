#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh" >&3 2>&1
    ./instance-data load

    MOCK_OUT="${LOG_DIR}/mock-http.out"
    export MOCK_OUT

    yq '
        .url="http://localhost:9999" |
        .group_wait="5s" |
        .group_threshold=2
    ' -i "${CONFIG_DIR}/notifications/http.yaml"

    yq '
        .notifications=["http_default"] |
        .filters=["Alert.GetScope() == \"Ip\""]
    ' -i "${CONFIG_DIR}/profiles.yaml"

    yq '
        .plugin_config.user="" |
        .plugin_config.group=""
    ' -i "${CONFIG_DIR}/config.yaml"

    rm -f -- "${MOCK_OUT}"

    ./instance-crowdsec start
    ./instance-mock-http start 9999
}

teardown_file() {
    load "../lib/teardown_file.sh" >&3 2>&1
    ./instance-mock-http stop
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "$FILE add two bans" {
    run -0 cscli decisions add --ip 1.2.3.4 --duration 30s
    assert_output --partial 'Decision successfully added'

    run -0 cscli decisions add --ip 1.2.3.5 --duration 30s
    assert_output --partial 'Decision successfully added'
    sleep 2
}

@test "$FILE expected 1 log line from http server" {
    run -0 wc -l <"${MOCK_OUT}"
    assert_output 1
}

@test "$FILE expected to receive 2 alerts in the request body from plugin" {
    run -0 jq -r '.request_body' <"${MOCK_OUT}"
    run -0 jq -r 'length' <(output)
    assert_output 2
}

@test "$FILE expected to receive IP 1.2.3.4 as value of first decision" {
    run -0 jq -r '.request_body[0].decisions[0].value' <"${MOCK_OUT}"
    assert_output 1.2.3.4
}

@test "$FILE expected to receive IP 1.2.3.5 as value of second decision" {
    run -0 jq -r '.request_body[1].decisions[0].value' <"${MOCK_OUT}"
    assert_output 1.2.3.5
}
