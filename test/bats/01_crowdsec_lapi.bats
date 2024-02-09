#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

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

@test "lapi (.api.server.enable=false)" {
    rune -0 config_set '.api.server.enable=false'
    rune -1 "${CROWDSEC}" -no-cs
    assert_stderr --partial "You must run at least the API Server or crowdsec"
}

@test "lapi (no .api.server.listen_uri)" {
    rune -0 config_set 'del(.api.server.listen_uri)'
    rune -1 "${CROWDSEC}" -no-cs
    assert_stderr --partial "no listen_uri specified"
}

@test "lapi (bad .api.server.listen_uri)" {
    rune -0 config_set '.api.server.listen_uri="127.0.0.1:-80"'
    rune -1 "${CROWDSEC}" -no-cs
    assert_stderr --partial "while starting API server: listening on 127.0.0.1:-80: listen tcp: address -80: invalid port"
}

@test "lapi (listen on random port)" {
    config_set '.common.log_media="stdout"'
    rune -0 config_set '.api.server.listen_uri="127.0.0.1:0"'
    rune -0 wait-for --err "CrowdSec Local API listening on 127.0.0.1:" "${CROWDSEC}" -no-cs
}

