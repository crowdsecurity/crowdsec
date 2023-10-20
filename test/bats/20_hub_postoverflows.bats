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
    hub_min=$(jq <"$HUB_DIR/.index.json" 'del(..|.content?) | del(..|.long_description?) | del(..|.deprecated?) | del (..|.labels?)')
    echo "$hub_min" >"$HUB_DIR/.index.json"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli postoverflows list" {
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
    expected=$(jq <"$HUB_DIR/.index.json" -r '.postoverflows | length')

    rune -0 cscli postoverflows list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli postoverflows list -o json -a
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "$expected"

    rune -0 cscli postoverflows list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"
}


@test "cscli postoverflows list [scenario]..." {
    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist

    # list one item
    rune -0 cscli postoverflows list crowdsecurity/rdns
    assert_output --partial "crowdsecurity/rdns"
    refute_output --partial "crowdsecurity/cdn-whitelist"

    # list multiple items
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist
    assert_output --partial "crowdsecurity/rdns"
    assert_output --partial "crowdsecurity/cdn-whitelist"

    rune -0 cscli postoverflows list crowdsecurity/rdns -o json
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "1"
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist -o json
    rune -0 jq '.postoverflows | length' <(output)
    assert_output "2"

    rune -0 cscli postoverflows list crowdsecurity/rdns -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli postoverflows list crowdsecurity/rdns crowdsecurity/cdn-whitelist -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli postoverflows list [scenario]... (not installed / not existing)" {
    skip "not implemented yet"
    # not installed
    rune -1 cscli postoverflows list crowdsecurity/rdns
    # not existing
    rune -1 cscli postoverflows list blahblah/blahblah
}

@test "cscli postoverflows install [scenario]..." {
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
    assert_stderr --partial "can't find 'crowdsecurity/rdnf' in postoverflows, did you mean crowdsecurity/rdns?"

    # install multiple
    rune -0 cscli postoverflows install crowdsecurity/rdns crowdsecurity/cdn-whitelist
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'installed: true'
    rune -0 cscli postoverflows inspect crowdsecurity/cdn-whitelist --no-metrics
    assert_output --partial 'crowdsecurity/cdn-whitelist'
    assert_output --partial 'installed: true'
}

@test "cscli postoverflows install [postoverflow]... (file location and download-only)" {
    # simple install
    rune -0 cscli postoverflows install crowdsecurity/rdns --download-only
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/postoverflows/s00-enrich/crowdsecurity/rdns.yaml"
    assert_file_not_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"

    rune -0 cscli postoverflows install crowdsecurity/rdns
    assert_file_exists "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
}


@test "cscli postoverflows inspect [scenario]..." {
    rune -1 cscli postoverflows inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    ./instance-crowdsec start

    rune -1 cscli postoverflows inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"

    # one item
    rune -0 cscli postoverflows inspect crowdsecurity/rdns --no-metrics
    assert_line 'type: postoverflows'
    assert_line 'stage: s00-enrich'
    assert_line 'name: crowdsecurity/rdns'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: postoverflows/s00-enrich/crowdsecurity/rdns.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli postoverflows inspect crowdsecurity/rdns
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o json
    rune -0 jq -c '[.type, .stage, .name, .author, .path, .installed]' <(output)
    # XXX: .installed is missing -- not false
    assert_json '["postoverflows","s00-enrich","crowdsecurity/rdns","crowdsecurity","postoverflows/s00-enrich/crowdsecurity/rdns.yaml",null]'

    # one item, raw
    rune -0 cscli postoverflows inspect crowdsecurity/rdns -o raw
    assert_line 'type: postoverflows'
    assert_line 'stage: s00-enrich'
    assert_line 'name: crowdsecurity/rdns'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: postoverflows/s00-enrich/crowdsecurity/rdns.yaml'
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
    assert_json '[["postoverflows","s00-enrich","crowdsecurity/rdns","crowdsecurity","postoverflows/s00-enrich/crowdsecurity/rdns.yaml",null],["postoverflows","s01-whitelist","crowdsecurity/cdn-whitelist","crowdsecurity","postoverflows/s01-whitelist/crowdsecurity/cdn-whitelist.yaml",null]]'

    # multiple items, raw
    rune -0 cscli postoverflows inspect crowdsecurity/rdns crowdsecurity/cdn-whitelist -o raw
    assert_output --partial 'crowdsecurity/rdns'
    assert_output --partial 'crowdsecurity/cdn-whitelist'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli postoverflows remove [postoverflow]..." {
    rune -1 cscli postoverflows remove
    assert_stderr --partial "specify at least one postoverflow to remove or '--all'"

    rune -1 cscli postoverflows remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"

    # XXX: we can however remove a real item if it's not installed, or already removed
    rune -0 cscli postoverflows remove crowdsecurity/rdns

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

@test "cscli postoverflows remove [parser]... --force" {
    # remove a parser that belongs to a collection
    rune -0 cscli collections install crowdsecurity/auditd
    rune -0 cscli postoverflows remove crowdsecurity/auditd-whitelisted-process
    assert_stderr --partial "crowdsecurity/auditd-whitelisted-process belongs to collections: [crowdsecurity/auditd]"
    assert_stderr --partial "Run 'sudo cscli postoverflows remove crowdsecurity/auditd-whitelisted-process --force' if you want to force remove this postoverflow"
}

@test "cscli postoverflows upgrade [postoverflow]..." {
    rune -1 cscli postoverflows upgrade
    assert_stderr --partial "specify at least one postoverflow to upgrade or '--all'"

    # XXX: should this return 1 instead of log.Error?
    rune -0 cscli postoverflows upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in postoverflows"

    # XXX: same message if the item exists but is not installed, this is confusing
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns
    assert_stderr --partial "can't find 'crowdsecurity/rdns' in postoverflows"

    # hash of an empty file
    sha256_empty="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # add version 0.0 to the hub
    new_hub=$(jq --arg DIGEST "$sha256_empty" <"$HUB_DIR/.index.json" '. * {postoverflows:{"crowdsecurity/rdns":{"versions":{"0.0":{"digest":$DIGEST, "deprecated": false}}}}}')
    echo "$new_hub" >"$HUB_DIR/.index.json"
 
    rune -0 cscli postoverflows install crowdsecurity/rdns

    # bring the file to v0.0
    truncate -s 0 "$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
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
    echo "dirty" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    echo "dirty" >"$CONFIG_DIR/postoverflows/s01-whitelist/cdn-whitelist.yaml"
    rune -0 cscli postoverflows list -o json
    rune -0 jq -e '[.postoverflows[].local_version]==["?","?"]' <(output)
    rune -0 cscli postoverflows upgrade crowdsecurity/rdns crowdsecurity/cdn-whitelist
    rune -0 jq -e '[.postoverflows[].local_version]==[.postoverflows[].version]' <(output)

    # upgrade all
    echo "dirty" >"$CONFIG_DIR/postoverflows/s00-enrich/rdns.yaml"
    echo "dirty" >"$CONFIG_DIR/postoverflows/s01-whitelist/cdn-whitelist.yaml"
    rune -0 cscli postoverflows upgrade --all
    rune -0 jq -e '[.postoverflows[].local_version]==[.postoverflows[].version]' <(output)
}
