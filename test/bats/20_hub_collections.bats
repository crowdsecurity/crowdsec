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

@test "cscli collections list" {
    # no items
    rune -0 cscli collections list
    assert_output --partial "COLLECTIONS"
    rune -0 cscli collections list -o json
    assert_json '{collections:[]}'
    rune -0 cscli collections list -o raw
    assert_output 'name,status,version,description'

    # some items
    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb

    rune -0 cscli collections list
    assert_output --partial crowdsecurity/sshd
    assert_output --partial crowdsecurity/smb
    rune -0 grep -c enabled <(output)
    assert_output "2"

    rune -0 cscli collections list -o json
    assert_output --partial crowdsecurity/sshd
    assert_output --partial crowdsecurity/smb
    rune -0 jq '.collections | length' <(output)
    assert_output "2"

    rune -0 cscli collections list -o raw
    assert_output --partial crowdsecurity/sshd
    assert_output --partial crowdsecurity/smb
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli collections list -a" {
    expected=$(jq <"$HUB_DIR/.index.json" -r '.collections | length')

    rune -0 cscli collections list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli collections list -o json -a
    rune -0 jq '.collections | length' <(output)
    assert_output "$expected"

    rune -0 cscli collections list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"
}


@test "cscli collections list [collection]..." {
    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb

    # list one item
    rune -0 cscli collections list crowdsecurity/sshd
    assert_output --partial "crowdsecurity/sshd"
    refute_output --partial "crowdsecurity/smb"

    # list multiple items
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb
    assert_output --partial "crowdsecurity/sshd"
    assert_output --partial "crowdsecurity/smb"

    rune -0 cscli collections list crowdsecurity/sshd -o json
    rune -0 jq '.collections | length' <(output)
    assert_output "1"
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb -o json
    rune -0 jq '.collections | length' <(output)
    assert_output "2"

    rune -0 cscli collections list crowdsecurity/sshd -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli collections list [collection]... (not installed / not existing)" {
    skip "not implemented yet"
    # not installed
    rune -1 cscli collections list crowdsecurity/sshd
    # not existing
    rune -1 cscli collections list blahblah/blahblah
}

@test "cscli collections install [collection]..." {
    rune -1 cscli collections install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # simple install
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'installed: true'

    # not in hub
    rune -1 cscli collections install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in collections"

    # autocorrect
    rune -1 cscli collections install crowdsecurity/ssshd
    assert_stderr --partial "can't find 'crowdsecurity/ssshd' in collections, did you mean crowdsecurity/sshd?"

    # install multiple
    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'installed: true'
    rune -0 cscli collections inspect crowdsecurity/smb --no-metrics
    assert_output --partial 'crowdsecurity/smb'
    assert_output --partial 'installed: true'
}

@test "cscli collections install [collection]... (file location and download-only)" {
    # simple install
    rune -0 cscli collections install crowdsecurity/linux --download-only
    rune -0 cscli collections inspect crowdsecurity/linux --no-metrics
    assert_output --partial 'crowdsecurity/linux'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/collections/crowdsecurity/linux.yaml"
    assert_file_not_exists "$CONFIG_DIR/collections/linux.yaml"

    rune -0 cscli collections install crowdsecurity/linux
    assert_file_exists "$CONFIG_DIR/collections/linux.yaml"
}


@test "cscli collections inspect [collection]..." {
    rune -1 cscli collections inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    ./instance-crowdsec start

    rune -1 cscli collections inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"

    # one item
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_line 'type: collections'
    assert_line 'name: crowdsecurity/sshd'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: collections/crowdsecurity/sshd.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli collections inspect crowdsecurity/sshd
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -c '[.type, .name, .author, .path, .installed]' <(output)
    # XXX: .installed is missing -- not false
    assert_json '["collections","crowdsecurity/sshd","crowdsecurity","collections/crowdsecurity/sshd.yaml",null]'

    # one item, raw
    rune -0 cscli collections inspect crowdsecurity/sshd -o raw
    assert_line 'type: collections'
    assert_line 'name: crowdsecurity/sshd'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: collections/crowdsecurity/sshd.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # multiple items
    rune -0 cscli collections inspect crowdsecurity/sshd crowdsecurity/smb --no-metrics
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'crowdsecurity/smb'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"

    # multiple items, with metrics
    rune -0 cscli collections inspect crowdsecurity/sshd crowdsecurity/smb
    rune -0 grep -c 'Current metrics:' <(output)
    assert_output "2"

    # multiple items, json
    rune -0 cscli collections inspect crowdsecurity/sshd crowdsecurity/smb -o json
    rune -0 jq -sc '[.[] | [.type, .name, .author, .path, .installed]]' <(output)
    assert_json '[["collections","crowdsecurity/sshd","crowdsecurity","collections/crowdsecurity/sshd.yaml",null],["collections","crowdsecurity/smb","crowdsecurity","collections/crowdsecurity/smb.yaml",null]]'

    # multiple items, raw
    rune -0 cscli collections inspect crowdsecurity/sshd crowdsecurity/smb -o raw
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'crowdsecurity/smb'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli collections remove [collection]..." {
    rune -1 cscli collections remove
    assert_stderr --partial "specify at least one collection to remove or '--all'"

    rune -1 cscli collections remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"

    # XXX: we can however remove a real item if it's not installed, or already removed
    rune -0 cscli collections remove crowdsecurity/sshd

    # install, then remove, check files
    rune -0 cscli collections install crowdsecurity/sshd
    assert_file_exists "$CONFIG_DIR/collections/sshd.yaml"
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_file_not_exists "$CONFIG_DIR/collections/sshd.yaml"

    # delete is an alias for remove
    rune -0 cscli collections install crowdsecurity/sshd
    assert_file_exists "$CONFIG_DIR/collections/sshd.yaml"
    rune -0 cscli collections delete crowdsecurity/sshd
    assert_file_not_exists "$CONFIG_DIR/collections/sshd.yaml"

    # purge
    assert_file_exists "$HUB_DIR/collections/crowdsecurity/sshd.yaml"
    rune -0 cscli collections remove crowdsecurity/sshd --purge
    assert_file_not_exists "$HUB_DIR/collections/crowdsecurity/sshd.yaml"

    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb

    # --all
    rune -0 cscli collections list -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"

    rune -0 cscli collections remove --all

    rune -0 cscli collections list -o raw
    rune -1 grep -vc 'name,status,version,description' <(output)
    assert_output "0"
}

