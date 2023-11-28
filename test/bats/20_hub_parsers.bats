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

@test "cscli parsers list" {
    hub_purge_all

    # no items
    rune -0 cscli parsers list
    assert_output --partial "PARSERS"
    rune -0 cscli parsers list -o json
    assert_json '{parsers:[]}'
    rune -0 cscli parsers list -o raw
    assert_output 'name,status,version,description'

    # some items
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    rune -0 cscli parsers list
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 grep -c enabled <(output)
    assert_output "2"

    rune -0 cscli parsers list -o json
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 jq '.parsers | length' <(output)
    assert_output "2"

    rune -0 cscli parsers list -o raw
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli parsers list -a" {
    expected=$(jq <"$INDEX_PATH" -r '.parsers | length')

    rune -0 cscli parsers list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli parsers list -o json -a
    rune -0 jq '.parsers | length' <(output)
    assert_output "$expected"

    rune -0 cscli parsers list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"

    # the list should be the same in all formats, and sorted (not case sensitive)

    list_raw=$(cscli parsers list -o raw -a | tail -n +2 | cut -d, -f1)
    list_human=$(cscli parsers list -o human -a | tail -n +6 | head -n -1 | cut -d' ' -f2)
    list_json=$(cscli parsers list -o json -a | jq -r '.parsers[].name')

    rune -0 sort -f <<<"$list_raw"
    assert_output "$list_raw"

    assert_equal "$list_raw" "$list_json"
    assert_equal "$list_raw" "$list_human"
}

@test "cscli parsers list [parser]..." {
    # non-existent
    rune -1 cscli parsers install foo/bar
    assert_stderr --partial "can't find 'foo/bar' in parsers"

    # not installed
    rune -0 cscli parsers list crowdsecurity/whitelists
    assert_output --regexp 'crowdsecurity/whitelists.*disabled'

    # install two items
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    # list an installed item
    rune -0 cscli parsers list crowdsecurity/whitelists
    assert_output --regexp "crowdsecurity/whitelists.*enabled"
    refute_output --partial "crowdsecurity/windows-auth"

    # list multiple installed and non installed items
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth crowdsecurity/traefik-logs
    assert_output --partial "crowdsecurity/whitelists"
    assert_output --partial "crowdsecurity/windows-auth"
    assert_output --partial "crowdsecurity/traefik-logs"

    rune -0 cscli parsers list crowdsecurity/whitelists -o json
    rune -0 jq '.parsers | length' <(output)
    assert_output "1"
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth crowdsecurity/traefik-logs -o json
    rune -0 jq '.parsers | length' <(output)
    assert_output "3"

    rune -0 cscli parsers list crowdsecurity/whitelists -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth crowdsecurity/traefik-logs -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "3"
}

@test "cscli parsers install" {
    rune -1 cscli parsers install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # not in hub
    rune -1 cscli parsers install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in parsers"

    # simple install
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'installed: true'

    # autocorrect
    rune -1 cscli parsers install crowdsecurity/sshd-logz
    assert_stderr --partial "can't find 'crowdsecurity/sshd-logz' in parsers, did you mean 'crowdsecurity/sshd-logs'?"

    # install multiple
    rune -0 cscli parsers install crowdsecurity/pgsql-logs crowdsecurity/postfix-logs
    rune -0 cscli parsers inspect crowdsecurity/pgsql-logs --no-metrics
    assert_output --partial 'crowdsecurity/pgsql-logs'
    assert_output --partial 'installed: true'
    rune -0 cscli parsers inspect crowdsecurity/postfix-logs --no-metrics
    assert_output --partial 'crowdsecurity/postfix-logs'
    assert_output --partial 'installed: true'
}

@test "cscli parsers install (file location and download-only)" {
    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics
    assert_output --partial 'installed: true'
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "cscli parsers install --force (tainted)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -1 cscli parsers install crowdsecurity/whitelists
    assert_stderr --partial "error while installing 'crowdsecurity/whitelists': while enabling crowdsecurity/whitelists: crowdsecurity/whitelists is tainted, won't enable unless --force"

    rune -0 cscli parsers install crowdsecurity/whitelists --force
    assert_stderr --partial "crowdsecurity/whitelists: overwrite"
    assert_stderr --partial "Enabled crowdsecurity/whitelists"
}

@test "cscli parsers install --ignore (skip on errors)" {
    rune -1 cscli parsers install foo/bar crowdsecurity/whitelists
    assert_stderr --partial "can't find 'foo/bar' in parsers"
    refute_stderr --partial "Enabled parsers: crowdsecurity/whitelists"

    rune -0 cscli parsers install foo/bar crowdsecurity/whitelists --ignore
    assert_stderr --partial "can't find 'foo/bar' in parsers"
    assert_stderr --partial "Enabled parsers: crowdsecurity/whitelists"
}

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
    assert_line 'stage: s01-parse'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'author: crowdsecurity'
    assert_line 'path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -c '[.type, .stage, .name, .author, .path, .installed]' <(output)
    assert_json '["parsers","s01-parse","crowdsecurity/sshd-logs","crowdsecurity","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",false]'

    # one item, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o raw
    assert_line 'type: parsers'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'stage: s01-parse'
    assert_line 'author: crowdsecurity'
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
    rune -0 jq -sc '[.[] | [.type, .stage, .name, .author, .path, .installed]]' <(output)
    assert_json '[["parsers","s01-parse","crowdsecurity/sshd-logs","crowdsecurity","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",false],["parsers","s02-enrich","crowdsecurity/whitelists","crowdsecurity","parsers/s02-enrich/crowdsecurity/whitelists.yaml",false]]'

    # multiple items, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists -o raw
    assert_output --partial 'crowdsecurity/sshd-logs'
    assert_output --partial 'crowdsecurity/whitelists'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli parsers remove" {
    rune -1 cscli parsers remove
    assert_stderr --partial "specify at least one parser to remove or '--all'"
    rune -1 cscli parsers remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"

    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_stderr --partial "removing crowdsecurity/whitelists: not installed -- no need to remove"

    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_stderr --partial "Removed crowdsecurity/whitelists"

    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_stderr --partial 'Removed source file [crowdsecurity/whitelists]'

    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_stderr --partial "removing crowdsecurity/whitelists: not installed -- no need to remove"

    rune -0 cscli parsers remove crowdsecurity/whitelists --purge --debug
    assert_stderr --partial 'removing crowdsecurity/whitelists: not downloaded -- no need to remove'
    refute_stderr --partial 'Removed source file [crowdsecurity/whitelists]'

    # install, then remove, check files
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    # delete is an alias for remove
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers delete crowdsecurity/whitelists
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    # purge
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_file_not_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"

    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    # --all
    rune -0 cscli parsers list -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"

    rune -0 cscli parsers remove --all

    rune -0 cscli parsers list -o raw
    rune -1 grep -vc 'name,status,version,description' <(output)
    assert_output "0"
}

@test "cscli parsers remove --force" {
    # remove a parser that belongs to a collection
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli parsers remove crowdsecurity/sshd-logs
    assert_stderr --partial "crowdsecurity/sshd-logs belongs to collections: [crowdsecurity/sshd]"
    assert_stderr --partial "Run 'sudo cscli parsers remove crowdsecurity/sshd-logs --force' if you want to force remove this parser"
}

@test "cscli parsers upgrade" {
    rune -1 cscli parsers upgrade
    assert_stderr --partial "specify at least one parser to upgrade or '--all'"
    rune -1 cscli parsers upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"
    rune -0 cscli parsers remove crowdsecurity/pam-logs --purge
    rune -1 cscli parsers upgrade crowdsecurity/pam-logs
    assert_stderr --partial "can't upgrade crowdsecurity/pam-logs: not installed"
    rune -0 cscli parsers install crowdsecurity/pam-logs --download-only
    rune -1 cscli parsers upgrade crowdsecurity/pam-logs
    assert_stderr --partial "can't upgrade crowdsecurity/pam-logs: downloaded but not installed"

    # hash of the string "v0.0"
    sha256_0_0="dfebecf42784a31aa3d009dbcec0c657154a034b45f49cf22a895373f6dbf63d"

    # add version 0.0 to all parsers
    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$INDEX_PATH" '.parsers |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$INDEX_PATH"
 
    rune -0 cscli parsers install crowdsecurity/whitelists

    echo "v0.0" > "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    # upgrade
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # taint
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    # XXX: should return error
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_stderr --partial "crowdsecurity/whitelists is tainted, --force to overwrite"
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    # force upgrade with taint
    rune -0 cscli parsers upgrade crowdsecurity/whitelists --force
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # multiple items
    rune -0 cscli parsers install crowdsecurity/windows-auth
    echo "v0.0" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    echo "v0.0" >"$CONFIG_DIR/parsers/s01-parse/windows-auth.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -e '[.parsers[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli parsers upgrade crowdsecurity/whitelists crowdsecurity/windows-auth
    rune -0 cscli parsers list -o json
    rune -0 jq -e 'any(.parsers[].local_version; .=="0.0") | not' <(output)

    # upgrade all
    echo "v0.0" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    echo "v0.0" >"$CONFIG_DIR/parsers/s01-parse/windows-auth.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -e '[.parsers[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli parsers upgrade --all
    rune -0 cscli parsers list -o json
    rune -0 jq -e 'any(.parsers[].local_version; .=="0.0") | not' <(output)
}
