#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
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
    :
}

#----------

@test "cscli hub list" {
    hub_purge_all

    # no items
    rune -0 cscli hub list
    assert_output "No items to display"
    rune -0 cscli hub list -o json
    assert_json '{"appsec-configs":[],"appsec-rules":[],parsers:[],scenarios:[],collections:[],contexts:[],postoverflows:[]}'
    rune -0 cscli hub list -o raw
    assert_output 'name,status,version,description,type'

    # some items: with output=human, show only non-empty tables
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli scenarios install crowdsecurity/telnet-bf
    rune -0 cscli hub list
    assert_output --regexp ".*PARSERS.*crowdsecurity/whitelists.*SCENARIOS.*crowdsecurity/telnet-bf.*"
    refute_output --partial 'POSTOVERFLOWS'
    refute_output --partial 'COLLECTIONS'

    rune -0 cscli hub list -o json
    rune -0 jq -e '(.parsers | length == 1) and (.scenarios | length == 1)' <(output)
    rune -0 cscli hub list -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    refute_output --partial 'crowdsecurity/iptables'

    # all items
    mkdir -p "$CONFIG_DIR/contexts"
    # there are no contexts yet, so we create a local one
    touch "$CONFIG_DIR/contexts/mycontext.yaml"
    rune -0 cscli hub list -a
    assert_output --regexp ".*PARSERS.*crowdsecurity/whitelists.*POSTOVERFLOWS.*SCENARIOS.*crowdsecurity/telnet-bf.*CONTEXTS.*mycontext.yaml.*COLLECTIONS.*crowdsecurity/iptables.*"
    rune -0 cscli hub list -a -o json
    rune -0 jq -e '(.parsers | length > 1) and (.scenarios | length > 1)' <(output)
    rune -0 cscli hub list -a -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    assert_output --partial 'crowdsecurity/iptables'
}

@test "cscli hub list (invalid index)" {
    new_hub=$(jq <"$INDEX_PATH" '."appsec-rules"."crowdsecurity/vpatch-laravel-debug-mode".version="999"')
    echo "$new_hub" >"$INDEX_PATH"
    rune -0 cscli hub list --error
    assert_stderr --partial "invalid hub item appsec-rules:crowdsecurity/vpatch-laravel-debug-mode: latest version missing from index"

    rune -1 cscli appsec-rules install crowdsecurity/vpatch-laravel-debug-mode --force
    assert_stderr --partial "appsec-rules:crowdsecurity/vpatch-laravel-debug-mode: latest hash missing from index. The index file is invalid, please run 'cscli hub update' and try again"
}

@test "missing reference in hub index" {
    new_hub=$(jq <"$INDEX_PATH" 'del(.parsers."crowdsecurity/smb-logs") | del (.scenarios."crowdsecurity/mysql-bf")')
    echo "$new_hub" >"$INDEX_PATH"
    rune -0 cscli hub list --error
    assert_stderr --partial "can't find parsers:crowdsecurity/smb-logs, required by crowdsecurity/smb"
    assert_stderr --partial "can't find scenarios:crowdsecurity/mysql-bf, required by crowdsecurity/mysql"
}

@test "loading hub reports tainted items (subitem is tainted)" {
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli hub list
    refute_stderr --partial "tainted"
    rune -0 truncate -s0 "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "crowdsecurity/sshd is tainted by parsers:crowdsecurity/sshd-logs"
}

@test "loading hub reports tainted items (subitem is not installed)" {
    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 cscli hub list
    refute_stderr --partial "tainted"
    rune -0 rm "$CONFIG_DIR/parsers/s01-parse/sshd-logs.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "crowdsecurity/sshd is tainted by missing parsers:crowdsecurity/sshd-logs"
}

@test "an install symlink can have a different name than the items it points to" {
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -r '.local_path' <(output)
    rune -0 mv "$output" "$CONFIG_DIR/scenarios/newname.yaml"
    rune -0 cscli hub list -o json
    rune -0 jq -r '.scenarios.[].name' <(output)
    assert_output 'crowdsecurity/ssh-bf'

    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -r '.installed' <(output)
    assert_output true

    rune -0 cscli scenarios remove crowdsecurity/ssh-bf
    assert_output - <<-EOT
	Action plan:
	❌ disable
	 scenarios: crowdsecurity/ssh-bf

	disabling scenarios:crowdsecurity/ssh-bf

	$RELOAD_MESSAGE
	EOT
    refute_stderr

    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -r '.installed' <(output)
    assert_output false
}

@test "cscli hub update" {
    rm -f "$INDEX_PATH"
    rune -0 cscli hub update
    assert_output "Downloading $INDEX_PATH"
    rune -0 cscli hub update
    assert_output "Nothing to do, the hub index is up to date."

    # hub update must honor the --error flag to be silent in noop cron jobs
    rune -0 cscli hub update --error
    refute_output
    refute_stderr
}

@test "cscli hub upgrade (up to date)" {
    rune -0 cscli hub upgrade
    assert_output - <<-EOT
	Action plan:
	🔄 check & update data files
	EOT

    rune -0 cscli parsers install crowdsecurity/syslog-logs
    rune -0 cscli hub upgrade --force
    assert_output - <<-EOT
	Action plan:
	🔄 check & update data files
	EOT

    # hub upgrade must honor the --error flag to be silent in noop cron jobs
    rune -0 cscli hub upgrade --error
    refute_output
    refute_stderr

    skip "todo: data files are re-downloaded with --force"
}

@test "cscli hub upgrade (with local items)" {
    mkdir -p "$CONFIG_DIR/collections"
    touch "$CONFIG_DIR/collections/foo.yaml"
    rune -0 cscli hub upgrade
    assert_output - <<-EOT
	collections:foo.yaml - not downloading local item
	Action plan:
	🔄 check & update data files
	EOT
}

@test "cscli hub types" {
    rune -0 cscli hub types -o raw
    assert_line "parsers"
    assert_line "postoverflows"
    assert_line "scenarios"
    assert_line "contexts"
    assert_line "collections"
    rune -0 cscli hub types -o human
    rune -0 yq -o json <(output)
    assert_json '["parsers","postoverflows","scenarios","contexts","appsec-configs","appsec-rules","collections"]'
    rune -0 cscli hub types -o json
    assert_json '["parsers","postoverflows","scenarios","contexts","appsec-configs","appsec-rules","collections"]'
}
