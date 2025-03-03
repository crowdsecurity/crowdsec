#!/usr/bin/env bats

# Generic tests for the command "cscli <hubtype> remove".
#
# Behavior that is specific to a hubtype should be tested in a separate file.


set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
#    INDEX_PATH=$(config_get '.config_paths.index_path')
#    export INDEX_PATH
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

#----------

@test "cscli <hubtype> remove (no argument)" {
    rune -1 cscli parsers remove
    refute_output
    assert_stderr --partial "specify at least one parser to remove or '--all'"
}

@test "cscli <hubtype> remove (aliased)" {
    rune -1 cscli parser remove
    refute_output
    assert_stderr --partial "specify at least one parser to remove or '--all'"
}

@test "cscli <hubtype> delete (alias of remove)" {
    rune -1 cscli parsers delete
    refute_output
    assert_stderr --partial "specify at least one parser to remove or '--all'"
}

@test "remove an item (non-existent)" {
    rune -1 cscli parsers remove foo/bar
    refute_output
    assert_stderr --partial "can't find 'foo/bar' in parsers"
}

@test "remove an item (not downloaded)" {
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.downloaded==false' <(output)

    rune -0 cscli parsers remove crowdsecurity/whitelists --dry-run
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists --force
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_output "Nothing to do."
    refute_stderr
}

@test "remove an item (not installed)" {
    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)

    rune -0 cscli parsers remove crowdsecurity/whitelists --dry-run
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists --force
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_output --partial "purging parsers:crowdsecurity/whitelists"
}

@test "remove an item (dry run)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers remove crowdsecurity/whitelists --dry-run
    assert_output - --regexp <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists
	
	Dry run, no action taken.
	EOT
    refute_stderr
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "remove an item" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_output - <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists

	disabling parsers:crowdsecurity/whitelists

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
}

@test "remove an item (purge)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_output - <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists
	🗑 purge (delete source)
	 parsers: crowdsecurity/whitelists

	disabling parsers:crowdsecurity/whitelists
	purging parsers:crowdsecurity/whitelists
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.downloaded==false' <(output)
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    assert_file_not_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
}

@test "remove multiple items" {
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth
    rune -0 cscli parsers remove crowdsecurity/whitelists crowdsecurity/windows-auth --dry-run
    assert_output - --regexp <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists, crowdsecurity/windows-auth
	
	Dry run, no action taken.
	EOT
    refute_stderr

    rune -0 cscli parsers remove crowdsecurity/whitelists crowdsecurity/windows-auth
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    rune -0 cscli parsers inspect crowdsecurity/windows-auth --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
}

@test "remove all items of a same type" {
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    rune -1 cscli parsers remove crowdsecurity/whitelists --all
    assert_stderr "Error: can't specify items and '--all' at the same time"

    rune -0 cscli parsers remove --all --dry-run
    assert_output - --regexp <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists, crowdsecurity/windows-auth
	
	Dry run, no action taken.
	EOT
    refute_stderr

    rune -0 cscli parsers remove --all
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    rune -0 cscli parsers inspect crowdsecurity/windows-auth --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
}

@test "remove an item (tainted, requires --force)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -1 cscli parsers remove crowdsecurity/whitelists --dry-run
    assert_stderr --partial "crowdsecurity/whitelists is tainted, use '--force' to remove"
    refute_output

    rune -1 cscli parsers remove crowdsecurity/whitelists
    assert_stderr --partial "crowdsecurity/whitelists is tainted, use '--force' to remove"
    refute_output

    rune -0 cscli parsers remove crowdsecurity/whitelists --force
    assert_output - <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/whitelists

	disabling parsers:crowdsecurity/whitelists
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
}

@test "remove an item that belongs to a collection (requires --force)" {
    rune -0 cscli collections install crowdsecurity/sshd
    # XXX: should exit with 1?
    rune -0 cscli parsers remove crowdsecurity/sshd-logs
    assert_output "Nothing to do."
    assert_stderr --partial "crowdsecurity/sshd-logs belongs to collections: [crowdsecurity/sshd]"
    assert_stderr --partial "Run 'sudo cscli parsers remove crowdsecurity/sshd-logs --force' if you want to force remove this parser"
    assert_file_exists "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"

    rune -0 cscli parsers remove crowdsecurity/sshd-logs --force
    assert_output - <<-EOT
	Action plan:
	❌ disable
	 parsers: crowdsecurity/sshd-logs

	disabling parsers:crowdsecurity/sshd-logs
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr
    assert_file_not_exists "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
}

@test "remove an item (autocomplete)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli __complete parsers remove crowd
    assert_stderr --partial '[Debug] parsers: [crowdsecurity/whitelists]'
    assert_output --partial 'crowdsecurity/whitelists'
}
