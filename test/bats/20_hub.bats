#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
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
    hub_strip_index
}

teardown() {
    :
}

#----------

@test "cscli hub list" {
    hub_purge_all

    # no items
    rune -0 cscli hub list
    assert_output --regexp ".*PARSERS.*POSTOVERFLOWS.*SCENARIOS.*COLLECTIONS.*"
    rune -0 cscli hub list -o json
    assert_json '{parsers:[],scenarios:[],collections:[],postoverflows:[]}'
    rune -0 cscli hub list -o raw
    assert_output 'name,status,version,description,type'

    # some items
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli scenarios install crowdsecurity/telnet-bf
    rune -0 cscli hub list
    assert_output --regexp ".*PARSERS.*crowdsecurity/whitelists.*POSTOVERFLOWS.*SCENARIOS.*crowdsecurity/telnet-bf.*COLLECTIONS.*"
    rune -0 cscli hub list -o json
    rune -0 jq -e '(.parsers | length == 1) and (.scenarios | length == 1)' <(output)
    rune -0 cscli hub list -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    refute_output --partial 'crowdsecurity/iptables'

    # all items
    rune -0 cscli hub list -a
    assert_output --regexp ".*PARSERS.*crowdsecurity/whitelists.*POSTOVERFLOWS.*SCENARIOS.*crowdsecurity/telnet-bf.*COLLECTIONS.*crowdsecurity/iptables.*"
    rune -0 cscli hub list -a -o json
    rune -0 jq -e '(.parsers | length > 1) and (.scenarios | length > 1)' <(output)
    rune -0 cscli hub list -a -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    assert_output --partial 'crowdsecurity/iptables'
}

@test "missing reference in hub index" {
    new_hub=$(jq <"$INDEX_PATH" 'del(.parsers."crowdsecurity/smb-logs") | del (.scenarios."crowdsecurity/mysql-bf")')
    echo "$new_hub" >"$INDEX_PATH"
    rune -0 cscli hub list --error
    assert_stderr --partial "can't find crowdsecurity/smb-logs in parsers, required by crowdsecurity/smb"
    assert_stderr --partial "can't find crowdsecurity/mysql-bf in scenarios, required by crowdsecurity/mysql"
}

@test "loading hub reports tainted items (subitem is tainted)" {
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli hub list
    refute_stderr --partial "tainted"
    rune -0 truncate -s0 "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "crowdsecurity/sshd is tainted because parsers:crowdsecurity/sshd-logs is tainted"
}

@test "loading hub reports tainted items (subitem is not installed)" {
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli hub list
    refute_stderr --partial "tainted"
    rune -0 rm "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "crowdsecurity/sshd is tainted because parsers:crowdsecurity/sshd-logs is missing"
}

@test "cscli hub update" {
    rm -f "$INDEX_PATH"
    rune -0 cscli hub update
    assert_stderr --partial "Wrote index to $INDEX_PATH"
    rune -0 cscli hub update
    assert_stderr --partial "hub index is up to date"
}

@test "cscli hub upgrade" {
    rune -0 cscli hub upgrade
    assert_stderr --partial "Upgrading parsers"
    assert_stderr --partial "Upgraded 0 parsers"
    assert_stderr --partial "Upgrading postoverflows"
    assert_stderr --partial "Upgraded 0 postoverflows"
    assert_stderr --partial "Upgrading scenarios"
    assert_stderr --partial "Upgraded 0 scenarios"
    assert_stderr --partial "Upgrading collections"
    assert_stderr --partial "Upgraded 0 collections"

    rune -0 cscli parsers install crowdsecurity/syslog-logs
    rune -0 cscli hub upgrade
    assert_stderr --partial "crowdsecurity/syslog-logs: up-to-date"

    rune -0 cscli hub upgrade --force
    assert_stderr --partial "crowdsecurity/syslog-logs: overwrite"
    assert_stderr --partial "crowdsecurity/syslog-logs: updated"
    assert_stderr --partial "Upgraded 1 parsers"
    # this is used by the cron script to know if the hub was updated
    assert_output --partial "updated crowdsecurity/syslog-logs"
}
