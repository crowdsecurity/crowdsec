#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

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
    hub_strip_index
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli collections list" {
    hub_purge_all

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
    expected=$(jq <"$INDEX_PATH" -r '.collections | length')

    rune -0 cscli collections list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli collections list -o json -a
    rune -0 jq '.collections | length' <(output)
    assert_output "$expected"

    rune -0 cscli collections list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"

    # the list should be the same in all formats, and sorted (not case sensitive)

    list_raw=$(cscli collections list -o raw -a | tail -n +2 | cut -d, -f1)
    list_human=$(cscli collections list -o human -a | tail -n +6 | head -n -1 | cut -d' ' -f2)
    list_json=$(cscli collections list -o json -a | jq -r '.collections[].name')

    rune -0 sort -f <<<"$list_raw"
    assert_output "$list_raw"

    assert_equal "$list_raw" "$list_json"
    assert_equal "$list_raw" "$list_human"
}

@test "cscli collections list [collection]..." {
    # non-existent
    rune -1 cscli collections install foo/bar
    assert_stderr --partial "can't find 'foo/bar' in collections"

    # not installed
    rune -0 cscli collections list crowdsecurity/smb
    assert_output --regexp 'crowdsecurity/smb.*disabled'

    # install two items
    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb

    # list an installed item
    rune -0 cscli collections list crowdsecurity/sshd
    assert_output --regexp "crowdsecurity/sshd"
    refute_output --partial "crowdsecurity/smb"

    # list multiple installed and non installed items
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb crowdsecurity/nginx
    assert_output --partial "crowdsecurity/sshd"
    assert_output --partial "crowdsecurity/smb"
    assert_output --partial "crowdsecurity/nginx"

    rune -0 cscli collections list crowdsecurity/sshd -o json
    rune -0 jq '.collections | length' <(output)
    assert_output "1"
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb crowdsecurity/nginx -o json
    rune -0 jq '.collections | length' <(output)
    assert_output "3"

    rune -0 cscli collections list crowdsecurity/sshd -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli collections list crowdsecurity/sshd crowdsecurity/smb -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli collections install" {
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
    assert_stderr --partial "can't find 'crowdsecurity/ssshd' in collections, did you mean 'crowdsecurity/sshd'?"

    # install multiple
    rune -0 cscli collections install crowdsecurity/sshd crowdsecurity/smb
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'installed: true'
    rune -0 cscli collections inspect crowdsecurity/smb --no-metrics
    assert_output --partial 'crowdsecurity/smb'
    assert_output --partial 'installed: true'
}

@test "cscli collections install (file location and download-only)" {
    rune -0 cscli collections install crowdsecurity/linux --download-only
    rune -0 cscli collections inspect crowdsecurity/linux --no-metrics
    assert_output --partial 'crowdsecurity/linux'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/collections/crowdsecurity/linux.yaml"
    assert_file_not_exists "$CONFIG_DIR/collections/linux.yaml"

    rune -0 cscli collections install crowdsecurity/linux
    rune -0 cscli collections inspect crowdsecurity/linux --no-metrics
    assert_output --partial 'installed: true'
    assert_file_exists "$CONFIG_DIR/collections/linux.yaml"
}

@test "cscli collections install --force (tainted)" {
    rune -0 cscli collections install crowdsecurity/sshd
    echo "dirty" >"$CONFIG_DIR/collections/sshd.yaml"

    rune -1 cscli collections install crowdsecurity/sshd
    assert_stderr --partial "error while installing 'crowdsecurity/sshd': while enabling crowdsecurity/sshd: crowdsecurity/sshd is tainted, won't enable unless --force"

    rune -0 cscli collections install crowdsecurity/sshd --force
    assert_stderr --partial "crowdsecurity/sshd: overwrite"
    assert_stderr --partial "Enabled crowdsecurity/sshd"
}

@test "cscli collections install --ignore (skip on errors)" {
    rune -1 cscli collections install foo/bar crowdsecurity/sshd
    assert_stderr --partial "can't find 'foo/bar' in collections"
    refute_stderr --partial "Enabled collections: crowdsecurity/sshd"

    rune -0 cscli collections install foo/bar crowdsecurity/sshd --ignore
    assert_stderr --partial "can't find 'foo/bar' in collections"
    assert_stderr --partial "Enabled collections: crowdsecurity/sshd"
}

@test "cscli collections inspect" {
    rune -1 cscli collections inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    # required for metrics
    ./instance-crowdsec start

    rune -1 cscli collections inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"

    # one item
    rune -0 cscli collections inspect crowdsecurity/sshd --no-metrics
    assert_line 'type: collections'
    assert_line 'name: crowdsecurity/sshd'
    assert_line 'author: crowdsecurity'
    assert_line 'path: collections/crowdsecurity/sshd.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli collections inspect crowdsecurity/sshd
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -c '[.type, .name, .author, .path, .installed]' <(output)
    assert_json '["collections","crowdsecurity/sshd","crowdsecurity","collections/crowdsecurity/sshd.yaml",false]'

    # one item, raw
    rune -0 cscli collections inspect crowdsecurity/sshd -o raw
    assert_line 'type: collections'
    assert_line 'name: crowdsecurity/sshd'
    assert_line 'author: crowdsecurity'
    assert_line 'path: collections/crowdsecurity/sshd.yaml'
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
    assert_json '[["collections","crowdsecurity/sshd","crowdsecurity","collections/crowdsecurity/sshd.yaml",false],["collections","crowdsecurity/smb","crowdsecurity","collections/crowdsecurity/smb.yaml",false]]'

    # multiple items, raw
    rune -0 cscli collections inspect crowdsecurity/sshd crowdsecurity/smb -o raw
    assert_output --partial 'crowdsecurity/sshd'
    assert_output --partial 'crowdsecurity/smb'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli collections remove" {
    rune -1 cscli collections remove
    assert_stderr --partial "specify at least one collection to remove or '--all'"
    rune -1 cscli collections remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"

    rune -0 cscli collections install crowdsecurity/sshd --download-only
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial 'removing crowdsecurity/sshd: not installed -- no need to remove'

    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial 'Removed crowdsecurity/sshd'

    rune -0 cscli collections remove crowdsecurity/sshd --purge
    assert_stderr --partial 'Removed source file [crowdsecurity/sshd]'

    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial 'removing crowdsecurity/sshd: not installed -- no need to remove'

    rune -0 cscli collections remove crowdsecurity/sshd --purge --debug
    assert_stderr --partial 'removing crowdsecurity/sshd: not downloaded -- no need to remove'
    refute_stderr --partial 'Removed source file [crowdsecurity/sshd]'

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

@test "cscli collections remove --force" {
    # remove a collections that belongs to a collection
    rune -0 cscli collections install crowdsecurity/linux
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial "crowdsecurity/sshd belongs to collections: [crowdsecurity/linux]"
    assert_stderr --partial "Run 'sudo cscli collections remove crowdsecurity/sshd --force' if you want to force remove this collection"
}

@test "cscli collections upgrade" {
    rune -1 cscli collections upgrade
    assert_stderr --partial "specify at least one collection to upgrade or '--all'"
    rune -1 cscli collections upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in collections"
    rune -0 cscli collections remove crowdsecurity/exim --purge
    rune -1 cscli collections upgrade crowdsecurity/exim
    assert_stderr --partial "can't upgrade crowdsecurity/exim: not installed"
    rune -0 cscli collections install crowdsecurity/exim --download-only
    rune -1 cscli collections upgrade crowdsecurity/exim
    assert_stderr --partial "can't upgrade crowdsecurity/exim: downloaded but not installed"

    # hash of the string "v0.0"
    sha256_0_0="dfebecf42784a31aa3d009dbcec0c657154a034b45f49cf22a895373f6dbf63d"

    # add version 0.0 to all collections
    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$INDEX_PATH" '.collections |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$INDEX_PATH"
 
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
