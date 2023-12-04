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

@test "cscli scenarios list" {
    hub_purge_all

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
    expected=$(jq <"$INDEX_PATH" -r '.scenarios | length')

    rune -0 cscli scenarios list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli scenarios list -o json -a
    rune -0 jq '.scenarios | length' <(output)
    assert_output "$expected"

    rune -0 cscli scenarios list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"

    # the list should be the same in all formats, and sorted (not case sensitive)

    list_raw=$(cscli scenarios list -o raw -a | tail -n +2 | cut -d, -f1)
    list_human=$(cscli scenarios list -o human -a | tail -n +6 | head -n -1 | cut -d' ' -f2)
    list_json=$(cscli scenarios list -o json -a | jq -r '.scenarios[].name')

    rune -0 sort -f <<<"$list_raw"
    assert_output "$list_raw"

    assert_equal "$list_raw" "$list_json"
    assert_equal "$list_raw" "$list_human"
}

@test "cscli scenarios list [scenario]..." {
    # non-existent
    rune -1 cscli scenario install foo/bar
    assert_stderr --partial "can't find 'foo/bar' in scenarios"
 
    # not installed
    rune -0 cscli scenarios list crowdsecurity/ssh-bf
    assert_output --regexp 'crowdsecurity/ssh-bf.*disabled'

    # install two items
    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf

    # list an installed item
    rune -0 cscli scenarios list crowdsecurity/ssh-bf
    assert_output --regexp "crowdsecurity/ssh-bf.*enabled"
    refute_output --partial "crowdsecurity/telnet-bf"

    # list multiple installed and non installed items
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf crowdsecurity/aws-bf crowdsecurity/aws-bf
    assert_output --partial "crowdsecurity/ssh-bf"
    assert_output --partial "crowdsecurity/telnet-bf"
    assert_output --partial "crowdsecurity/aws-bf"

    rune -0 cscli scenarios list crowdsecurity/ssh-bf -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output "1"
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf crowdsecurity/aws-bf -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output "3"

    rune -0 cscli scenarios list crowdsecurity/ssh-bf -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/telnet-bf crowdsecurity/aws-bf -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "3"
}

@test "cscli scenarios install" {
    rune -1 cscli scenarios install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # not in hub
    rune -1 cscli scenarios install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in scenarios"

    # simple install
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: true'

    # autocorrect
    rune -1 cscli scenarios install crowdsecurity/ssh-tf
    assert_stderr --partial "can't find 'crowdsecurity/ssh-tf' in scenarios, did you mean 'crowdsecurity/ssh-bf'?"

    # install multiple
    rune -0 cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/telnet-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: true'
    rune -0 cscli scenarios inspect crowdsecurity/telnet-bf --no-metrics
    assert_output --partial 'crowdsecurity/telnet-bf'
    assert_output --partial 'installed: true'
}

@test "cscli scenarios install (file location and download-only)" {
    # simple install
    rune -0 cscli scenarios install crowdsecurity/ssh-bf --download-only
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/scenarios/crowdsecurity/ssh-bf.yaml"
    assert_file_not_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_output --partial 'installed: true'
    assert_file_exists "$CONFIG_DIR/scenarios/ssh-bf.yaml"
}

@test "cscli scenarios install --force (tainted)" {
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    echo "dirty" >"$CONFIG_DIR/scenarios/ssh-bf.yaml"

    rune -1 cscli scenarios install crowdsecurity/ssh-bf
    assert_stderr --partial "error while installing 'crowdsecurity/ssh-bf': while enabling crowdsecurity/ssh-bf: crowdsecurity/ssh-bf is tainted, won't enable unless --force"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf --force
    assert_stderr --partial "crowdsecurity/ssh-bf: overwrite"
    assert_stderr --partial "Enabled crowdsecurity/ssh-bf"
}

@test "cscli scenarios install --ignore (skip on errors)" {
    rune -1 cscli scenarios install foo/bar crowdsecurity/ssh-bf
    assert_stderr --partial "can't find 'foo/bar' in scenarios"
    refute_stderr --partial "Enabled scenarios: crowdsecurity/ssh-bf"

    rune -0 cscli scenarios install foo/bar crowdsecurity/ssh-bf --ignore
    assert_stderr --partial "can't find 'foo/bar' in scenarios"
    assert_stderr --partial "Enabled scenarios: crowdsecurity/ssh-bf"
}

@test "cscli scenarios inspect" {
    rune -1 cscli scenarios inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    # required for metrics
    ./instance-crowdsec start

    rune -1 cscli scenarios inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in scenarios"

    # one item
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics
    assert_line 'type: scenarios'
    assert_line 'name: crowdsecurity/ssh-bf'
    assert_line 'author: crowdsecurity'
    assert_line 'path: scenarios/crowdsecurity/ssh-bf.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -c '[.type, .name, .author, .path, .installed]' <(output)
    assert_json '["scenarios","crowdsecurity/ssh-bf","crowdsecurity","scenarios/crowdsecurity/ssh-bf.yaml",false]'

    # one item, raw
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o raw
    assert_line 'type: scenarios'
    assert_line 'name: crowdsecurity/ssh-bf'
    assert_line 'author: crowdsecurity'
    assert_line 'path: scenarios/crowdsecurity/ssh-bf.yaml'
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
    assert_json '[["scenarios","crowdsecurity/ssh-bf","crowdsecurity","scenarios/crowdsecurity/ssh-bf.yaml",false],["scenarios","crowdsecurity/telnet-bf","crowdsecurity","scenarios/crowdsecurity/telnet-bf.yaml",false]]'

    # multiple items, raw
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/telnet-bf -o raw
    assert_output --partial 'crowdsecurity/ssh-bf'
    assert_output --partial 'crowdsecurity/telnet-bf'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli scenarios remove" {
    rune -1 cscli scenarios remove
    assert_stderr --partial "specify at least one scenario to remove or '--all'"
    rune -1 cscli scenarios remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in scenarios"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf --download-only
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_stderr --partial "removing crowdsecurity/ssh-bf: not installed -- no need to remove"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_stderr --partial "Removed crowdsecurity/ssh-bf"

    rune -0 cscli scenarios remove crowdsecurity/ssh-bf --purge
    assert_stderr --partial 'Removed source file [crowdsecurity/ssh-bf]'

    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_stderr --partial "removing crowdsecurity/ssh-bf: not installed -- no need to remove"

    rune -0 cscli scenarios remove crowdsecurity/ssh-bf --purge --debug
    assert_stderr --partial 'removing crowdsecurity/ssh-bf: not downloaded -- no need to remove'
    refute_stderr --partial 'Removed source file [crowdsecurity/ssh-bf]'

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

@test "cscli scenarios remove --force" {
    # remove a scenario that belongs to a collection
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_stderr --partial "crowdsecurity/ssh-bf belongs to collections: [crowdsecurity/sshd]"
    assert_stderr --partial "Run 'sudo cscli scenarios remove crowdsecurity/ssh-bf --force' if you want to force remove this scenario"
}

@test "cscli scenarios upgrade" {
    rune -1 cscli scenarios upgrade
    assert_stderr --partial "specify at least one scenario to upgrade or '--all'"
    rune -1 cscli scenarios upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in scenarios"
    rune -0 cscli scenarios remove crowdsecurity/vsftpd-bf --purge
    rune -1 cscli scenarios upgrade crowdsecurity/vsftpd-bf
    assert_stderr --partial "can't upgrade crowdsecurity/vsftpd-bf: not installed"
    rune -0 cscli scenarios install crowdsecurity/vsftpd-bf --download-only
    rune -1 cscli scenarios upgrade crowdsecurity/vsftpd-bf
    assert_stderr --partial "can't upgrade crowdsecurity/vsftpd-bf: downloaded but not installed"

    # hash of the string "v0.0"
    sha256_0_0="dfebecf42784a31aa3d009dbcec0c657154a034b45f49cf22a895373f6dbf63d"

    # add version 0.0 to all scenarios
    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$INDEX_PATH" '.scenarios |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$INDEX_PATH"
 
    rune -0 cscli scenarios install crowdsecurity/ssh-bf

    echo "v0.0" > "$CONFIG_DIR/scenarios/ssh-bf.yaml"
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    # upgrade
    rune -0 cscli scenarios upgrade crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # taint
    echo "dirty" >"$CONFIG_DIR/scenarios/ssh-bf.yaml"
    # XXX: should return error
    rune -0 cscli scenarios upgrade crowdsecurity/ssh-bf
    assert_stderr --partial "crowdsecurity/ssh-bf is tainted, --force to overwrite"
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    # force upgrade with taint
    rune -0 cscli scenarios upgrade crowdsecurity/ssh-bf --force
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # multiple items
    rune -0 cscli scenarios install crowdsecurity/telnet-bf
    echo "v0.0" >"$CONFIG_DIR/scenarios/ssh-bf.yaml"
    echo "v0.0" >"$CONFIG_DIR/scenarios/telnet-bf.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq -e '[.scenarios[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/telnet-bf
    rune -0 cscli scenarios list -o json
    rune -0 jq -e 'any(.scenarios[].local_version; .=="0.0") | not' <(output)

    # upgrade all
    echo "v0.0" >"$CONFIG_DIR/scenarios/ssh-bf.yaml"
    echo "v0.0" >"$CONFIG_DIR/scenarios/telnet-bf.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq -e '[.scenarios[].local_version]==["0.0","0.0"]' <(output)
    rune -0 cscli scenarios upgrade --all
    rune -0 cscli scenarios list -o json
    rune -0 jq -e 'any(.scenarios[].local_version; .=="0.0") | not' <(output)
}
