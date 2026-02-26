#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

# Tests for LAPI configuration and startup

@test "lapi health check" {
    rune -0 ./instance-crowdsec start
    rune -0 curl "$(config_get '.api.server.listen_uri')"/health
    assert_json '{"status":"up"}'
}

@test "lapi (.api.server.enable=false)" {
    rune -0 config_set '.api.server.enable=false'
    rune -1 "$CROWDSEC" -no-cs
    assert_stderr --partial "you must run at least the API Server or crowdsec"
}

@test "lapi (no .api.server.listen_uri)" {
    rune -0 config_set 'del(.api.server.listen_socket) | del(.api.server.listen_uri)'
    rune -1 "$CROWDSEC" -no-cs
    assert_stderr --partial "no listen_uri or listen_socket specified"
}

@test "lapi (bad .api.server.listen_uri)" {
    rune -0 config_set 'del(.api.server.listen_socket) | .api.server.listen_uri="127.0.0.1:-80"'
    rune -1 "$CROWDSEC" -no-cs
    assert_stderr --partial "local API server stopped with error: listening on 127.0.0.1:-80: listen tcp: address -80: invalid port"
}

@test "lapi (socket path too long)" {
    LONG_NAME="12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    export LONG_NAME
    rune -0 config_set '.api.server.listen_socket = strenv(BATS_FILE_TMPDIR) + "/" + strenv(LONG_NAME)'
    rune -1 "$CROWDSEC" -no-cs
    assert_stderr --partial "local API server stopped with error: listen unix $BATS_FILE_TMPDIR/$LONG_NAME: bind: invalid argument (path length exceeds system limit"
}

@test "lapi (listen on random port)" {
    config_set '.common.log_media="stdout"'
    rune -0 config_set 'del(.api.server.listen_socket) | .api.server.listen_uri="127.0.0.1:0"'
    rune -0 wait-for --err "CrowdSec Local API listening on 127.0.0.1:" "$CROWDSEC" -no-cs
}
