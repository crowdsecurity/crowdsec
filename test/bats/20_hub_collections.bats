#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
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
    hub_min=$(jq <"$HUB_DIR/.index.json" 'del(..|.content?) | del(..|.long_description?) | del(..|.deprecated?) | del (..|.labels?)')
    echo "$hub_min" >"$HUB_DIR/.index.json"
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

    # not in hub
    rune -1 cscli collections install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in collections"

    # simple install
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'installed: true'

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

@test "cscli collections remove [collections]... --force" {
    # remove a collections that belongs to a collection
    rune -0 cscli collections install crowdsecurity/linux
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial "crowdsecurity/sshd belongs to collections: [crowdsecurity/linux]"
    assert_stderr --partial "Run 'sudo cscli collections remove crowdsecurity/sshd --force' if you want to force remove this collection"
}

@test "cscli collections upgrade [collection]..." {
    rune -1 cscli collections upgrade
    assert_stderr --partial "specify at least one collection to upgrade or '--all'"

    # XXX: should this return 1 instead of log.Error?
    rune -0 cscli collections upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"

    # XXX: same message if the item exists but is not installed, this is confusing
    rune -0 cscli collections upgrade crowdsecurity/sshd
    assert_stderr --partial "can't find 'crowdsecurity/sshd' in collections"

    # hash of the string "v0.0"
    sha256_0_0="dfebecf42784a31aa3d009dbcec0c657154a034b45f49cf22a895373f6dbf63d"

    # add version 0.0 to all collections
    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$HUB_DIR/.index.json" '.collections |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$HUB_DIR/.index.json"
 
    rune -0 cscli collections install crowdsecurity/sshd

    echo "v0.0" > "$CONFIG_DIR/collections/sshd.yaml"
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    # upgrade
    rune -0 cscli collections upgrade crowdsecurity/sshd
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # taint
    echo "dirty" >"$CONFIG_DIR/collections/sshd.yaml"
    # XXX: should return error
    rune -0 cscli collections upgrade crowdsecurity/sshd
    assert_stderr --partial "crowdsecurity/sshd is tainted, --force to overwrite"
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    # force upgrade with taint
    rune -0 cscli collections upgrade crowdsecurity/sshd --force
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # multiple items
    rune -0 cscli collections install crowdsecurity/smb
    echo "v0.0" >"$CONFIG_DIR/collections/sshd.yaml"
    echo "v0.0" >"$CONFIG_DIR/collections/smb.yaml"
    rune -0 cscli collections list -o json
    rune -0 jq -e '[.collections[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli collections upgrade crowdsecurity/sshd crowdsecurity/smb
    rune -0 cscli collections list -o json
    rune -0 jq -e 'any(.collections[].local_version; .=="0.0") | not' <(output)

    # upgrade all
    echo "v0.0" >"$CONFIG_DIR/collections/sshd.yaml"
    echo "v0.0" >"$CONFIG_DIR/collections/smb.yaml"
    rune -0 cscli collections list -o json
    rune -0 jq -e '[.collections[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli collections upgrade --all
    rune -0 cscli collections list -o json
    rune -0 jq -e 'any(.collections[].local_version; .=="0.0") | not' <(output)
}
