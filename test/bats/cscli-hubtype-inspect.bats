#!/usr/bin/env bats

# Generic tests for the command "cscli <hubtype> inspect".
#
# Behavior that is specific to a hubtype should be tested in a separate file.

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
    INDEX_PATH=$(config_get '.config_paths.index_path')
    export INDEX_PATH
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    export CONFIG_DIR
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

@test "cscli parsers inspect" {
    rune -1 cscli parsers inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    # required for metrics
    ./instance-crowdsec start

    rune -1 cscli parsers inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"

    # one item
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs --no-metrics
    assert_line 'type: parsers'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -c '[.type, .name, .path, .installed]' <(output)
    assert_json '["parsers","crowdsecurity/sshd-logs","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",false]'

    # one item, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o raw
    assert_line 'type: parsers'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # multiple items
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/sshd-logs'
    assert_output --partial 'crowdsecurity/whitelists'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"

    # multiple items, with metrics
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists
    rune -0 grep -c 'Current metrics:' <(output)
    assert_output "2"

    # multiple items, json
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists -o json
    rune -0 jq -sc '[.[] | [.type, .name, .path, .installed]]' <(output)
    assert_json '[["parsers","crowdsecurity/sshd-logs","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",false],["parsers","crowdsecurity/whitelists","parsers/s02-enrich/crowdsecurity/whitelists.yaml",false]]'

    # multiple items, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists -o raw
    assert_output --partial 'crowdsecurity/sshd-logs'
    assert_output --partial 'crowdsecurity/whitelists'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}
