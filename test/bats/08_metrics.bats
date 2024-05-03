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
    assert_stderr --partial 'Error: failed to fetch metrics: executing GET request for URL "http://127.0.0.1:6060/metrics" failed: Get "http://127.0.0.1:6060/metrics": dial tcp 127.0.0.1:6060: connect: connection refused'
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

@test "cscli metrics" {
    rune -0 ./instance-crowdsec start
    rune -0 cscli lapi status
    rune -0 cscli metrics
    assert_output --partial "Route"
    assert_output --partial '/v1/watchers/login'
    assert_output --partial "Local API Metrics:"

    rune -0 cscli metrics -o json
    rune -0 jq 'keys' <(output)
    assert_output --partial '"alerts",'
    assert_output --partial '"parsers",'

    rune -0 cscli metrics -o raw
    assert_output --partial 'alerts: {}'
    assert_output --partial 'parsers: {}'
}

@test "cscli metrics list" {
    rune -0 cscli metrics list
    assert_output --regexp "Type.*Title.*Description"

    rune -0 cscli metrics list -o json
    rune -0 jq -c '.[] | [.type,.title]' <(output)
    assert_line '["acquisition","Acquisition Metrics"]'

    rune -0 cscli metrics list -o raw
    assert_line "- type: acquisition"
    assert_line "  title: Acquisition Metrics"
}

@test "cscli metrics show" {
    rune -0 ./instance-crowdsec start
    rune -0 cscli lapi status

    assert_equal "$(cscli metrics)" "$(cscli metrics show)"

    rune -1 cscli metrics show foobar
    assert_stderr --partial "unknown metrics type: foobar"

    rune -0 cscli metrics show lapi
    assert_output --partial "Local API Metrics:"
    assert_output --regexp "Route.*Method.*Hits"
    assert_output --regexp "/v1/watchers/login.*POST"

    rune -0 cscli metrics show lapi -o json
    rune -0 jq -c '.lapi."/v1/watchers/login" | keys' <(output)
    assert_json '["POST"]'

    rune -0 cscli metrics show lapi -o raw
    assert_line 'lapi:'
    assert_line '    /v1/watchers/login:'
}
