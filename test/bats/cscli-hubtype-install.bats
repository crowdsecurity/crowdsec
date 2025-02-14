#!/usr/bin/env bats

# Generic tests for the command "cscli <hubtype> install".
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

get_latest_version() {
    local hubtype=$1
    shift
    local item_name=$1
    shift

    cscli "$hubtype" inspect "$item_name" -o json | jq -r '.version'
}

#----------

@test "cscli <hubtype> install (no argument)" {
    rune -1 cscli parsers install
    refute_output
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
}

@test "cscli <hubtype> install (aliased)" {
    rune -1 cscli parser install
    refute_output
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
}

@test "install an item (non-existent)" {
    rune -1 cscli parsers install foo/bar
    assert_stderr --partial "can't find 'foo/bar' in parsers"
}

@test "install an item (dry run)" {
    rune -0 cscli parsers install crowdsecurity/whitelists --dry-run
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists ($latest_whitelists)
	✅ enable
	 parsers: crowdsecurity/whitelists
	
	Dry run, no action taken.
	EOT
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "install an item (dry-run, de-duplicate commands)" {
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/whitelists --dry-run --output raw
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download parsers:crowdsecurity/whitelists ($latest_whitelists)
	✅ enable parsers:crowdsecurity/whitelists
	
	Dry run, no action taken.
	EOT
    refute_stderr
}

@test "install an item" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists ($latest_whitelists)
	✅ enable
	 parsers: crowdsecurity/whitelists

	downloading parsers:crowdsecurity/whitelists
	enabling parsers:crowdsecurity/whitelists
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "install an item (autocorrect)" {
    rune -1 cscli parsers install crowdsecurity/whatelists
    assert_stderr --partial "can't find 'crowdsecurity/whatelists' in parsers, did you mean 'crowdsecurity/whitelists'?"
    refute_output
}

@test "install an item (download only)" {
    assert_file_not_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists ($latest_whitelists)

	downloading parsers:crowdsecurity/whitelists
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==false' <(output)
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
}

@test "install an item (already installed)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers install crowdsecurity/whitelists --dry-run
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_output "Nothing to do."
    refute_stderr
}

@test "install an item (force is no-op if not tainted)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_output "Nothing to do."
    refute_stderr
    rune -0 cscli parsers install crowdsecurity/whitelists --force
    assert_output "Nothing to do."
    refute_stderr
}

@test "install an item (tainted, requires --force)" {
    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers install crowdsecurity/whitelists --dry-run
    assert_output - --stderr <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Nothing to do.
	EOT
    refute_stderr

    # XXX should this fail with status 1 instead?
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_output - <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Nothing to do.
	EOT
    refute_stderr

    rune -0 cscli parsers install crowdsecurity/whitelists --force
    latest_whitelists=$(get_latest_version parsers crowdsecurity/whitelists)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/whitelists (? -> $latest_whitelists)

	downloading parsers:crowdsecurity/whitelists
		
	$RELOAD_MESSAGE
	EOT
    refute_stderr
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
}

@test "install multiple items" {
    rune -0 cscli parsers install crowdsecurity/pgsql-logs crowdsecurity/postfix-logs
    rune -0 cscli parsers inspect crowdsecurity/pgsql-logs --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
    rune -0 cscli parsers inspect crowdsecurity/postfix-logs --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
}

@test "install multiple items (some already installed)" {
    rune -0 cscli parsers install crowdsecurity/pgsql-logs
    rune -0 cscli parsers install crowdsecurity/pgsql-logs crowdsecurity/postfix-logs --dry-run
    latest_postfix=$(get_latest_version parsers crowdsecurity/postfix-logs)
    assert_output - <<-EOT
	Action plan:
	📥 download
	 parsers: crowdsecurity/postfix-logs ($latest_postfix)
	✅ enable
	 parsers: crowdsecurity/postfix-logs
	
	Dry run, no action taken.
	EOT
    refute_stderr
}

@test "install one or multiple items (ignore errors)" {
    rune -0 cscli parsers install foo/bar --ignore
    assert_stderr --partial "can't find 'foo/bar' in parsers"
    assert_output "Nothing to do."

    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    # XXX: this is not testing '--ignore' anymore; TODO find a better error to ignore
    # and maybe re-evaluate the --ignore flag
    rune -0 cscli parsers install crowdsecurity/whitelists --ignore
    assert_output - <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Nothing to do.
	EOT
    refute_stderr

    # error on one item, should still install the others
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/pgsql-logs --ignore
    refute_stderr
    latest_pgsql=$(get_latest_version parsers crowdsecurity/pgsql-logs)
    assert_output - <<-EOT
	WARN parsers:crowdsecurity/whitelists is tainted, use '--force' to overwrite
	Action plan:
	📥 download
	 parsers: crowdsecurity/pgsql-logs ($latest_pgsql)
	✅ enable
	 parsers: crowdsecurity/pgsql-logs

	downloading parsers:crowdsecurity/pgsql-logs
	enabling parsers:crowdsecurity/pgsql-logs

	$RELOAD_MESSAGE
	EOT
    rune -0 cscli parsers inspect crowdsecurity/pgsql-logs --no-metrics -o json
    rune -0 jq -e '.installed==true' <(output)
}

@test "override part of a collection with local items" {
    # A collection will use a local item to fulfil a dependency provided it has
    # the correct name field.

    mkdir -p "$CONFIG_DIR/parsers/s01-parse"
    echo "name: crowdsecurity/sshd-logs" > "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -c '.parsers[] | [.name,.status]' <(output)
    assert_json '["crowdsecurity/sshd-logs","enabled,local"]'

    # attempt to install from hub
    rune -0 cscli parsers install crowdsecurity/sshd-logs
    assert_line 'parsers:crowdsecurity/sshd-logs - not downloading local item'
    rune -0 cscli parsers list -o json
    rune -0 jq -c '.parsers[] | [.name,.status]' <(output)
    assert_json '["crowdsecurity/sshd-logs","enabled,local"]'

    # attempt to install from a collection
    rune -0 cscli collections install crowdsecurity/sshd
    assert_line 'parsers:crowdsecurity/sshd-logs - not downloading local item'

    # verify it installed the rest of the collection
    assert_line 'enabling contexts:crowdsecurity/bf_base'
    assert_line 'enabling collections:crowdsecurity/sshd'

    # remove them
    rune -0 cscli collections delete crowdsecurity/sshd --force --purge
    rune -0 rm "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"

    # do the same with a different file name
    echo "name: crowdsecurity/sshd-logs" > "$CONFIG_DIR/parsers/s01-parse/something.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -c '.parsers[] | [.name,.status]' <(output)
    assert_json '["crowdsecurity/sshd-logs","enabled,local"]'

    # attempt to install from hub
    rune -0 cscli parsers install crowdsecurity/sshd-logs
    assert_line 'parsers:crowdsecurity/sshd-logs - not downloading local item'

    # attempt to install from a collection
    rune -0 cscli collections install crowdsecurity/sshd
    assert_line 'parsers:crowdsecurity/sshd-logs - not downloading local item'

    # verify it installed the rest of the collection
    assert_line 'enabling contexts:crowdsecurity/bf_base'
    assert_line 'enabling collections:crowdsecurity/sshd'
}

@test "a local item can override an official one, if it's not installed" {
    mkdir -p "$CONFIG_DIR/parsers/s02-enrich"
    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    echo "name: crowdsecurity/whitelists" > "$CONFIG_DIR/parsers/s02-enrich/hi.yaml"
    # no warning
    rune -0 cscli parsers list
    refute_stderr
    rune -0 cscli parsers list -o json
    rune -0 jq -e '.installed,.local==true,true' <(output)
}

@test "conflicting item names: local and non local - the local one has priority" {
    mkdir -p "$CONFIG_DIR/parsers/s02-enrich"
    rune -0 cscli parsers install crowdsecurity/whitelists
    echo "name: crowdsecurity/whitelists" > "$CONFIG_DIR/parsers/s02-enrich/hi.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -e '.installed,.local==true,true' <(output)
    rune -0 cscli parsers list
    assert_stderr --partial "multiple parsers named crowdsecurity/whitelists: ignoring $CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "conflicting item names: both local, the last one wins" {
    mkdir -p "$CONFIG_DIR/parsers/s02-enrich"
    echo "name: crowdsecurity/whitelists" > "$CONFIG_DIR/parsers/s02-enrich/one.yaml"
    echo "name: crowdsecurity/whitelists" > "$CONFIG_DIR/parsers/s02-enrich/two.yaml"
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -r '.local_path' <(output)
    assert_output --partial "/parsers/s02-enrich/two.yaml"
    rune -0 cscli parsers list
    assert_stderr --partial "multiple parsers named crowdsecurity/whitelists: ignoring $CONFIG_DIR/parsers/s02-enrich/one.yaml"
}
