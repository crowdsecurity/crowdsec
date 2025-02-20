#!/usr/bin/env bats

# Generic tests for the upgrade of hub items and data files.
#
# Commands under test:
#    cscli <hubype> upgrade
#
# This file should test behavior that can be applied to all types.

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
    # make sure the hub is empty
    hub_purge_all
}

teardown() {
    # most tests don't need the service, but we ensure it's stopped
    ./instance-crowdsec stop
}

hub_inject_v0() {
    # add a version 0.0 to all parsers

    # hash of the string "v0.0"
    sha256_0_0="daa1832414a685d69269e0ae15024b908f4602db45f9900e9c6e7f204af207c0"

    new_hub=$(jq --arg DIGEST "$sha256_0_0" <"$INDEX_PATH" '.parsers |= with_entries(.value.versions["0.0"] = {"digest": $DIGEST, "deprecated": false})')
    echo "$new_hub" >"$INDEX_PATH"
}

install_v0() {
    local hubtype=$1
    shift
    local item_name=$1
    shift

    cscli "$hubtype" install "$item_name"
    printf "%s" "v0.0" > "$(jq -r '.local_path' <(cscli "$hubtype" inspect "$item_name" --no-metrics -o json))"
}

get_latest_version() {
    local hubtype=$1
    shift
    local item_name=$1
    shift

    cscli "$hubtype" inspect "$item_name" -o json | jq -r '.version'
}

#----------

@test "cscli <hubtype> upgrade (no argument)" {
    rune -1 cscli parsers upgrade
    refute_output
    assert_stderr --partial "specify at least one parser to upgrade or '--all'"
}

@test "cscli <hubtype> upgrade (aliased)" {
    rune -1 cscli parser upgrade
    refute_output
    assert_stderr --partial "specify at least one parser to upgrade or '--all'"
}

@test "upgrade an item (non-existent)" {
    rune -1 cscli parsers upgrade foo/bar
    assert_stderr --partial "can't find 'foo/bar' in parsers"
}

@test "upgrade an item (non installed)" {
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)

    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists ($latest_whitelists)

	downloading parsers:crowdsecurity/whitelists

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_output 'Nothing to do.'
    refute_stderr
}

@test "upgrade an item (up-to-date)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers upgrade crowdsecurity/whitelists --dry-run
    assert_output 'Nothing to do.'
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_output 'Nothing to do.'
}

@test "upgrade an item (dry run)" {
    hub_inject_v0
    install_v0 parsers crowdsecurity/whitelists
    latest=$(get_latest_version parsers crowdsecurity/whitelists)

    rune -0 cscli parsers upgrade crowdsecurity/whitelists --dry-run
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists (0.0 -> $latest)
	
	Dry run, no action taken.
	EOT
    refute_stderr
}

@test "upgrade an item" {
    hub_inject_v0
    install_v0 parsers crowdsecurity/whitelists

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists (0.0 -> $latest_whitelists)

	downloading parsers:crowdsecurity/whitelists

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json

    # the version is now the latest
    rune -0 jq -e '.local_version==.version' <(output)
}

@test "upgrade an item (tainted, requires --force)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    rune -0 cscli parsers upgrade crowdsecurity/whitelists --dry-run
    assert_output - <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Nothing to do.
	EOT
    refute_stderr

    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_output - <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Nothing to do.
	EOT
    refute_stderr

    rune -0 cscli parsers upgrade crowdsecurity/whitelists --force
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists (? -> 0.2)

	downloading parsers:crowdsecurity/whitelists

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)
}

@test "upgrade multiple items" {
    hub_inject_v0
 
    install_v0 parsers crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)

    install_v0 parsers crowdsecurity/sshd-logs
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)
    latest_sshd=$(get_latest_version parsers crowdsecurity/sshd-logs)

    rune -0 cscli parsers upgrade crowdsecurity/whitelists crowdsecurity/sshd-logs --dry-run
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/sshd-logs (0.0 -> $latest_sshd), crowdsecurity/whitelists (0.0 -> $latest_whitelists)
	
	Dry run, no action taken.
	EOT
    refute_stderr

    rune -0 cscli parsers upgrade crowdsecurity/whitelists crowdsecurity/sshd-logs
    latest_sshd=$(get_latest_version parsers crowdsecurity/sshd-logs)
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/sshd-logs (0.0 -> $latest_sshd), crowdsecurity/whitelists (0.0 -> $latest_whitelists)

	downloading parsers:crowdsecurity/whitelists
	downloading parsers:crowdsecurity/sshd-logs
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -e '.local_version==.version' <(output)
}

@test "upgrade all items of the same type" {
    hub_inject_v0
 
    install_v0 parsers crowdsecurity/whitelists
    install_v0 parsers crowdsecurity/sshd-logs
    install_v0 parsers crowdsecurity/windows-auth

    rune -0 cscli parsers upgrade --all
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/sshd-logs (0.0 -> 2.9), crowdsecurity/whitelists (0.0 -> 0.2), crowdsecurity/windows-auth (0.0 -> 0.2)

	downloading parsers:crowdsecurity/sshd-logs
	downloading parsers:crowdsecurity/whitelists
	downloading parsers:crowdsecurity/windows-auth

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -e '.local_version==.version' <(output)

    rune -0 cscli parsers inspect crowdsecurity/windows-auth -o json
    rune -0 jq -e '.local_version==.version' <(output)
}

@test "upgrade an item (autocomplete)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli __complete parsers upgrade crowd
    assert_stderr --partial '[Debug] parsers: [crowdsecurity/whitelists]'
    assert_output --partial 'crowdsecurity/whitelists'
}

