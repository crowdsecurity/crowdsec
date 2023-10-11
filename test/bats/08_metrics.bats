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
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli metrics (crowdsec not running)" {
    rune -1 cscli metrics
    # crowdsec is down
    assert_stderr --partial 'failed to fetch prometheus metrics: executing GET request for URL \"http://127.0.0.1:6060/metrics\" failed: Get \"http://127.0.0.1:6060/metrics\": dial tcp 127.0.0.1:6060: connect: connection refused'
}

@test "cscli metrics (bad configuration)" {
    config_set '.prometheus.foo="bar"'
    rune -1 cscli metrics
    assert_stderr --partial "field foo not found in type csconfig.PrometheusCfg"
}

@test "cscli metrics (.prometheus.enabled=false)" {
    config_set '.prometheus.enabled=false'
    rune -1 cscli metrics
    assert_stderr --partial "prometheus is not enabled, can't show metrics"
}

@test "cscli metrics (missing listen_addr)" {
    config_set 'del(.prometheus.listen_addr)'
    rune -0 ./instance-crowdsec start
    rune -0 cscli metrics --debug
    assert_stderr --partial "prometheus.listen_addr is empty, defaulting to 127.0.0.1"
}

@test "cscli metrics (missing listen_port)" {
    config_set 'del(.prometheus.listen_port)'
    rune -0 ./instance-crowdsec start
    rune -0 cscli metrics --debug
    assert_stderr --partial "prometheus.listen_port is empty or zero, defaulting to 6060"
}

@test "cscli metrics (missing prometheus section)" {
    config_set 'del(.prometheus)'
    rune -1 cscli metrics
    assert_stderr --partial "prometheus is not enabled, can't show metrics"
}
