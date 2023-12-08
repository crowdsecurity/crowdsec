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

@test "cscli postoverflows list" {
    hub_purge_all

    # no items
    rune -0 cscli postoverflows list
    assert_output --partial "POSTOVERFLOWS"
    rune -0 cscli postoverflows list -o json
    assert_json '{postoverflows:[]}'
    rune -0 cscli postoverflows list -o raw
    assert_output 'name,status,version,description'

    # some items
    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist

    rune -0 cscli postoverflows list
    assert_output --partial crowdsecurity/rdns
    assert_output --partial crowdsecurity/cdn-whitelist
    rune -0 grep -c enabled <(output)
    assert_output "2"

    rune -0 cscli postoverflows list -o json
    assert_output --partial crowdsecurity/rdns
    assert_output --partial crowdsecurity/cdn-whitelist
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "2"

    rune -0 cscli postoverflows list -o raw
    assert_output --partial crowdsecurity/rdns
    assert_output --partial crowdsecurity/cdn-whitelist
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli postoverflows list -a" {
    expected=$(jq <"$INDEX_PATH" -r '.postoverflows | length')

    rune -0 cscli postoverflows list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli postoverflows list -o json -a
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "$expected"

    rune -0 cscli postoverflows list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"

    # the list should be the same in all formats, and sorted (not case sensitive)

    list_raw=$(cscli postoverflows list -o raw -a | tail -n +2 | cut -d, -f1)
    list_human=$(cscli postoverflows list -o human -a | tail -n +6 | head -n -1 | cut -d' ' -f2)
    list_json=$(cscli postoverflows list -o json -a | jq -r '.postoverflows[].name')

    rune -0 sort -f <<<"$list_raw"
    assert_output "$list_raw"

    assert_equal "$list_raw" "$list_json"
    assert_equal "$list_raw" "$list_human"
}

@test "cscli postoverflows list [postoverflow]..." {
    # non-existent
    rune -1 cscli postoverflows install foo/bar
    assert_stderr --partial "can't find 'foo/bar' in postoverflows"

    # not installed
    rune -0 cscli postoverflows list crowdsecurity/rdns
    assert_output --regexp 'crowdsecurity/rdns.*disabled'

    # install two items
    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist

    # list an installed item
    rune -0 cscli postoverflows list crowdsecurity/rdns
    assert_output --regexp "crowdsecurity/rdns.*enabled"
    refute_output --partial "crowdsecurity/cdn-whitelist"

    # list multiple installed and non installed items
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist crowdsecurity/ipv6_to_range
    assert_output --partial "crowdsecurity/rdns"
    assert_output --partial "crowdsecurity/cdn-whitelist"
    assert_output --partial "crowdsecurity/ipv6_to_range"

    rune -0 cscli postoverflows list crowdsecurity/rdns -o json
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "1"
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist crowdsecurity/ipv6_to_range -o json
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "3"

    rune -0 cscli postoverflows list crowdsecurity/rdns -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist crowdsecurity/ipv6_to_range -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "3"
}

@test "cscli postoverflows install" {
    rune -1 cscli postoverflows install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # not in hub
    rune -1 cscli postoverflows install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in postoverflows"

    # simple install
    rune -0 cscli postoverflows install crowdsecurity/rdns
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'installed: true'

    # autocorrect
    rune -1 cscli postoverflows install crowdsecurity/rdnf
    assert_stderr --partial "can't find 'crowdsecurity/rdnf' in postoverflows, did you mean 'crowdsecurity/rdns'?"

    # install multiple
    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'installed: true'
    rune -0 cscli postoverflows inspect crowdsecurity/cdn-whitelist --no-metrics
    assert_output --partial 'crowdsecurity/cdn-whitelist'
    assert_output --partial 'installed: true'
}

@test "cscli postoverflows install (file location and download-only)" {
    rune -0 cscli postoverflows install crowdsecurity/rdns --download-only
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/postoverflows/s00-enrich/crowdsecurity/rdns.yaml"
    assert_file_not_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"

    rune -0 cscli postoverflows install crowdsecurity/rdns
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'installed: true'
    assert_file_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
}

@test "cscli postoverflows install --force (tainted)" {
    rune -0 cscli postoverflows install crowdsecurity/rdns
    echo "dirty" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"

    rune -1 cscli postoverflows install crowdsecurity/rdns
    assert_stderr --partial "error while installing 'crowdsecurity/rdns': while enabling crowdsecurity/rdns: crowdsecurity/rdns is tainted, won't enable unless --force"

    rune -0 cscli postoverflows install crowdsecurity/rdns --force
    assert_stderr --partial "crowdsecurity/rdns: overwrite"
    assert_stderr --partial "Enabled crowdsecurity/rdns"
}

@test "cscli postoverflow install --ignore (skip on errors)" {
    rune -1 cscli postoverflows install foo/bar crowdsecurity/rdns
    assert_stderr --partial "can't find 'foo/bar' in postoverflows"
    refute_stderr --partial "Enabled postoverflows: crowdsecurity/rdns"

    rune -0 cscli postoverflows install foo/bar crowdsecurity/rdns --ignore
    assert_stderr --partial "can't find 'foo/bar' in postoverflows"
    assert_stderr --partial "Enabled postoverflows: crowdsecurity/rdns"
}

@test "cscli postoverflows inspect" {
    rune -1 cscli postoverflows inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    # required for metrics
    ./instance-crowdsec start

    rune -1 cscli postoverflows inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"

    # one item
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_line 'type: postoverflows'
    assert_line 'stage: s00-enrich'
    assert_line 'name: crowdsecurity/rdns'
    assert_line 'author: crowdsecurity'
    assert_line 'path: postoverflows/s00-enrich/crowdsecurity/rdns.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli postoverflows inspect crowdsecurity/rdns
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -c '[.type, .stage, .name, .author, .path, .installed]' <(output)
    assert_json '["postoverflows","s00-enrich","crowdsecurity/rdns","crowdsecurity","postoverflows/s00-enrich/crowdsecurity/rdns.yaml",false]'

    # one item, raw
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o raw
    assert_line 'type: postoverflows'
    assert_line 'name: crowdsecurity/rdns'
    assert_line 'stage: s00-enrich'
    assert_line 'author: crowdsecurity'
    assert_line 'path: postoverflows/s00-enrich/crowdsecurity/rdns.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # multiple items
    rune -0 cscli postoverflows inspect crowdsecurity/rdns crowdsecurity/cdn-whitelist --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'crowdsecurity/cdn-whitelist'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"

    # multiple items, with metrics
    rune -0 cscli postoverflows inspect crowdsecurity/rdns crowdsecurity/cdn-whitelist
    rune -0 grep -c 'Current metrics:' <(output)
    assert_output "2"

    # multiple items, json
    rune -0 cscli postoverflows inspect crowdsecurity/rdns crowdsecurity/cdn-whitelist -o json
    rune -0 jq -sc '[.[] | [.type, .stage, .name, .author, .path, .installed]]' <(output)
    assert_json '[["postoverflows","s00-enrich","crowdsecurity/rdns","crowdsecurity","postoverflows/s00-enrich/crowdsecurity/rdns.yaml",false],["postoverflows","s01-whitelist","crowdsecurity/cdn-whitelist","crowdsecurity","postoverflows/s01-whitelist/crowdsecurity/cdn-whitelist.yaml",false]]'

    # multiple items, raw
    rune -0 cscli postoverflows inspect crowdsecurity/rdns crowdsecurity/cdn-whitelist -o raw
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'crowdsecurity/cdn-whitelist'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli postoverflows remove" {
    rune -1 cscli postoverflows remove
    assert_stderr --partial "specify at least one postoverflow to remove or '--all'"
    rune -1 cscli postoverflows remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"

    rune -0 cscli postoverflows install crowdsecurity/rdns --download-only
    rune -0 cscli postoverflows remove crowdsecurity/rdns
    assert_stderr --partial "removing crowdsecurity/rdns: not installed -- no need to remove"

    rune -0 cscli postoverflows install crowdsecurity/rdns
    rune -0 cscli postoverflows remove crowdsecurity/rdns
    assert_stderr --partial 'Removed crowdsecurity/rdns'

    rune -0 cscli postoverflows remove crowdsecurity/rdns --purge
    assert_stderr --partial 'Removed source file [crowdsecurity/rdns]'

    rune -0 cscli postoverflows remove crowdsecurity/rdns
    assert_stderr --partial 'removing crowdsecurity/rdns: not installed -- no need to remove'

    rune -0 cscli postoverflows remove crowdsecurity/rdns --purge --debug
    assert_stderr --partial 'removing crowdsecurity/rdns: not downloaded -- no need to remove'
    refute_stderr --partial 'Removed source file [crowdsecurity/rdns]'

    # install, then remove, check files
    rune -0 cscli postoverflows install crowdsecurity/rdns
    assert_file_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    rune -0 cscli postoverflows remove crowdsecurity/rdns
    assert_file_not_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"

    # delete is an alias for remove
    rune -0 cscli postoverflows install crowdsecurity/rdns
    assert_file_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    rune -0 cscli postoverflows delete crowdsecurity/rdns
    assert_file_not_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"

    # purge
    assert_file_exists "$HUB_DIR/postoverflows/s00-enrich/crowdsecurity/rdns.yaml"
    rune -0 cscli postoverflows remove crowdsecurity/rdns --purge
    assert_file_not_exists "$HUB_DIR/postoverflows/s00-enrich/crowdsecurity/rdns.yaml"

    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist

    # --all
    rune -0 cscli postoverflows list -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"

    rune -0 cscli postoverflows remove --all

    rune -0 cscli postoverflows list -o raw
    rune -1 grep -vc 'name,status,version,description' <(output)
    assert_output "0"
}

@test "cscli postoverflows remove --force" {
    # remove a postoverflow that belongs to a collection
    rune -0 cscli collections install crowdsecurity/auditd
    rune -0 cscli postoverflows remove crowdsecurity/auditd-whitelisted-process
    assert_stderr --partial "crowdsecurity/auditd-whitelisted-process belongs to collections: [crowdsecurity/auditd]"
    assert_stderr --partial "Run 'sudo cscli postoverflows remove crowdsecurity/auditd-whitelisted-process --force' if you want to force remove this postoverflow"
}

@test "cscli postoverflows upgrade" {
    rune -1 cscli postoverflows upgrade
    assert_stderr --partial "specify at least one postoverflow to upgrade or '--all'"
    rune -1 cscli postoverflows upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"
    rune -0 cscli postoverflows remove crowdsecurity/discord-crawler-whitelist --purge
    rune -1 cscli postoverflows upgrade crowdsecurity/discord-crawler-whitelist
    assert_stderr --partial "can't upgrade crowdsecurity/discord-crawler-whitelist: not installed"
    rune -0 cscli postoverflows install crowdsecurity/discord-crawler-whitelist --download-only
    rune -1 cscli postoverflows upgrade crowdsecurity/discord-crawler-whitelist
    assert_stderr --partial "can't upgrade crowdsecurity/discord-crawler-whitelist: downloaded but not installed"

    # hash of the string "v0.0"
    sha256_0_0="dfebecf42784a31aa3d009dbcec0c657154a034b45f49cf22a895373f6dbf63d"

    # add version 0.0 to all postoverflows
    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$INDEX_PATH" '.postoverflows |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$INDEX_PATH"
 
    rune -0 cscli postoverflows install crowdsecurity/rdns

    echo "v0.0" > "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    # upgrade
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # taint
    echo "dirty" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    # XXX: should return error
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns
    assert_stderr --partial "crowdsecurity/rdns is tainted, --force to overwrite"
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    # force upgrade with taint
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns --force
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # multiple items
    rune -0 cscli postoverflows install crowdsecurity/cdn-whitelist
    echo "v0.0" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    echo "v0.0" >"$CONFIG_DIR/postoverflows/s01-whitelist/cdn-whitelist.yaml"
    rune -0 cscli postoverflows list -o json
    rune -0 jq -e '[.postoverflows[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns crowdsecurity/cdn-whitelist
    rune -0 cscli postoverflows list -o json
    rune -0 jq -e 'any(.postoverflows[].local_version; .=="0.0") | not' <(output)

    # upgrade all
    echo "v0.0" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    echo "v0.0" >"$CONFIG_DIR/postoverflows/s01-whitelist/cdn-whitelist.yaml"
    rune -0 cscli postoverflows list -o json
    rune -0 jq -e '[.postoverflows[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli postoverflows upgrade --all
    rune -0 cscli postoverflows list -o json
    rune -0 jq -e 'any(.postoverflows[].local_version; .=="0.0") | not' <(output)
}
