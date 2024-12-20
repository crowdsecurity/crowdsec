#!/usr/bin/env bats

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

    # use python to sort because it handles "_" like go
    rune -0 python3 -c 'import sys; print("".join(sorted(sys.stdin.readlines(), key=str.casefold)), end="")' <<<"$list_raw"
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
