#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load

    MOCK_OUT="${LOG_DIR}/mock-http.out"
    export MOCK_OUT
    MOCK_PORT="9999"
    MOCK_URL="http://localhost:${MOCK_PORT}"
    export MOCK_URL
    PLUGIN_DIR=$(config_get '.config_paths.plugin_dir')
    PLUGIN_DIR=$(realpath "$PLUGIN_DIR")
    export PLUGIN_DIR

    config_set "$(config_get '.config_paths.notification_dir')/http.yaml" '
        .type="http" |
        .url=strenv(MOCK_URL) |
        .group_wait="5s" |
        .group_threshold=2 |
        .format="{\"url_query_params\": {\"msg\": \"{{range $i, $v := .}}{{if $i}},{{end}}{{$v.Source.Value}} banned for {{$v.Scenario}}{{end}}\"}}"
    '

    config_set "$(config_get '.api.server.profiles_path')" '
        .notifications=["http_default"] |
        .filters=["Alert.GetScope() == \"Ip\""]
    '

    config_set '
        .plugin_config.user="" |
        .plugin_config.group=""
    '

    rm -f -- "$MOCK_OUT"

    ./instance-crowdsec start
    ./instance-mock-http start "$MOCK_PORT"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    ./instance-crowdsec stop
    ./instance-mock-http stop
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "add two bans" {
    rune -0 cscli decisions add --ip 1.2.3.4 --duration 30s
    assert_stderr --partial 'Decision successfully added'

    rune -0 cscli decisions add --ip 1.2.3.5 --duration 30s
    assert_stderr --partial 'Decision successfully added'
    sleep 5
}

@test "expected 1 log line from http server" {
    rune -0 wc -l <"$MOCK_OUT"
    rune -0 tr -d ' ' < <(output)
    assert_output 1
}

@test "expected query params with msg containing both IPs" {
    rune -0 jq -r '.path' <"$MOCK_OUT"
    assert_output --regexp '^/\?msg='
    assert_output --partial '1.2.3.4'
    assert_output --partial '1.2.3.5'
    assert_output --partial 'banned'
}

@test "expected empty request body" {
    rune -0 jq -r '.request_body' <"$MOCK_OUT"
    assert_output null
}
