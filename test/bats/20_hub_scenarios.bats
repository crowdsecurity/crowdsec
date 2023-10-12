#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
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
    hub_uninstall_all
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli scenarios list" {
    # no items
    rune -0 cscli scenarios list
    assert_output --partial "SCENARIOS"
    rune -0 cscli scenarios list -o json
    assert_json '{scenarios:[]}'
    rune -0 cscli scenarios list -o raw
    assert_output 'name,status,version,description'

    # some items
    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf

    rune -0 cscli scenarios list
    assert_output --partial crowdsecurity/ssh-bf
    assert_output --partial crowdsecurity/telnet-bf
    rune -0 grep -c enabled <(output)
    assert_output "2"

    rune -0 cscli scenarios list -o json
    assert_output --partial crowdsecurity/ssh-bf
    assert_output --partial crowdsecurity/telnet-bf
    rune -0 jq '.scenarios | length' <(output)
    assert_output "2"

    rune -0 cscli scenarios list -o raw
    assert_output --partial crowdsecurity/ssh-bf
    assert_output --partial crowdsecurity/telnet-bf
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli scenarios list -a" {
    expected=$(jq <"$HUB_DIR/.index.json" -r '.scenarios | length')

    rune -0 cscli scenarios list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli scenarios list -o json -a
    rune -0 jq '.scenarios | length' <(output)
    assert_output "$expected"

    rune -0 cscli scenarios list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"
}


@test "cscli scenarios list [scenario]..." {
    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf

    # list one item
    rune -0 cscli scenarios list crowdsecurity/ssh-bf
    assert_output --partial "crowdsecurity/ssh-bf"
    refute_output --partial "crowdsecurity/telnet-bf"

    # list multiple items
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf
    assert_output --partial "crowdsecurity/ssh-bf"
    assert_output --partial "crowdsecurity/telnet-bf"

    rune -0 cscli scenarios list crowdsecurity/ssh-bf -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output "1"
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output "2"

    rune -0 cscli scenarios list crowdsecurity/ssh-bf -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli scenarios list [scenario]... (not installed / not existing)" {
    skip "not implemented yet"
    # not installed
    rune -1 cscli scenarios list crowdsecurity/ssh-bf
    # not existing
    rune -1 cscli scenarios list blahblah/blahblah
}

@test "cscli scenarios install [scenario]..." {
    rune -1 cscli scenarios install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # simple install
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: true'

    # not in hub
    rune -1 cscli scenarios install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in scenarios"

    # autocorrect
    rune -1 cscli scenarios install crowdsecurity/ssh-tf
    assert_stderr --partial "can't find 'crowdsecurity/ssh-tf' in scenarios, did you mean crowdsecurity/ssh-bf?"

    # install multiple
    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: true'
    rune -0 cscli scenarios inspect crowdsecurity/telnet-bf --no-metrics
    assert_output --partial 'crowdsecurity/telnet-bf'
    assert_output --partial 'installed: true'
}


@test "cscli scenarios install [scenario]... (file location and download-only)" {
    # simple install
    rune -0 cscli scenarios install crowdsecurity/ssh-bf --download-only
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/scenarios/crowdsecurity/ssh-bf.yaml"
    assert_file_not_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    assert_file_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"
}


@test "cscli scenarios inspect [scenario]..." {
    rune -1 cscli scenarios inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    ./instance-crowdsec start

    rune -1 cscli scenarios inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in scenarios"

    # one item
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_line 'type: scenarios'
    assert_line 'name: crowdsecurity/ssh-bf'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: scenarios/crowdsecurity/ssh-bf.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -c '[.type, .name, .author, .path, .installed]' <(output)
    # XXX: .installed is missing -- not false
    assert_json '["scenarios","crowdsecurity/ssh-bf","crowdsecurity","scenarios/crowdsecurity/ssh-bf.yaml",null]'

    # one item, raw
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o raw
    assert_line 'type: scenarios'
    assert_line 'name: crowdsecurity/ssh-bf'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: scenarios/crowdsecurity/ssh-bf.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # multiple items
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/telnet-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'crowdsecurity/telnet-bf'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"

    # multiple items, with metrics
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/telnet-bf
    rune -0 grep -c 'Current metrics:' <(output)
    assert_output "2"

    # multiple items, json
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/telnet-bf -o json
    rune -0 jq -sc '[.[] | [.type, .name, .author, .path, .installed]]' <(output)
    assert_json '[["scenarios","crowdsecurity/ssh-bf","crowdsecurity","scenarios/crowdsecurity/ssh-bf.yaml",null],["scenarios","crowdsecurity/telnet-bf","crowdsecurity","scenarios/crowdsecurity/telnet-bf.yaml",null]]'

    # multiple items, raw
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/telnet-bf -o raw
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'crowdsecurity/telnet-bf'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli scenarios remove [scenario]..." {
    rune -1 cscli scenarios remove
    assert_stderr --partial "specify at least one scenario to remove or '--all'"

    rune -1 cscli scenarios remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in scenarios"

    # XXX: we can however remove a real item if it's not installed, or already removed
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf

    # install, then remove, check files
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    assert_file_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_file_not_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"

    # delete is an alias for remove
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    assert_file_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"
    rune -0 cscli scenarios delete crowdsecurity/ssh-bf
    assert_file_not_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"

    # purge
    assert_file_exists "$HUB_DIR/scenarios/crowdsecurity/ssh-bf.yaml"
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf --purge
    assert_file_not_exists "$HUB_DIR/scenarios/crowdsecurity/ssh-bf.yaml"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf

    # --all
    rune -0 cscli scenarios list -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"

    rune -0 cscli scenarios remove --all

    rune -0 cscli scenarios list -o raw
    rune -1 grep -vc 'name,status,version,description' <(output)
    assert_output "0"
}

