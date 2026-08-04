#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    config_enable_capi

    config_set "$(config_get '.api.server.online_client.credentials_path')" '
    .url="https://api.crowdsec.net/" |
    .login="test" |
    .password="test"
    '
}

#----------

@test "cscli console status" {
    # credentials point to CAPI with dummy login/password, so the live console section
    # falls back gracefully (unreachable) while the sharing options are always shown.
    rune -0 cscli console status
    assert_output --partial "Console connection"
    assert_output --partial "Central API (CAPI)"
    assert_output --partial "Option Name"
    assert_output --partial "Activated"
    assert_output --partial "Description"
    assert_output --partial "custom"
    assert_output --partial "manual"
    assert_output --partial "tainted"
    assert_output --partial "context"
    # decision management is no longer a sharing option
    refute_output --partial "console_management"
    rune -0 cscli console status -o json
    assert_json - <<- EOT
	{
	"console": {
	"registered": true,
	"authenticated": false,
	"decision_management": false,
	"enrolled": false,
	"plan": ""
	},
	"sharing_options": {
	"context": false,
	"custom": true,
	"manual": false,
	"tainted": true
	}
	}
	EOT
    rune -0 cscli console status -o raw
    assert_output - <<-EOT
	option,enabled
	manual,false
	custom,true
	tainted,true
	context,false
	EOT
}

@test "cscli console status: not registered" {
    # blank credentials -> the engine is not registered against CAPI; status must still
    # succeed, report the state, and show the sharing options instead of erroring out.
    creds=$(config_get '.api.server.online_client.credentials_path')
    echo "" > "$creds"
    rune -0 cscli console status
    assert_output --partial "cscli capi register"
    assert_output --partial "custom"
    rune -0 cscli console status -o json
    rune -0 jq -r '.console.registered' <(output)
    assert_output "false"
}

@test "cscli console status: missing credentials file does not error" {
    # a missing credentials file must degrade to the same table, not a hard error
    creds=$(config_get '.api.server.online_client.credentials_path')
    rm -f "$creds"
    rune -0 cscli console status
    assert_output --partial "cscli capi register"
    assert_output --partial "custom"
    rune -0 cscli console status -o json
    rune -0 jq -r '.console.registered' <(output)
    assert_output "false"
}

@test "cscli console enable" {
    rune -0 cscli console enable manual --debug
    assert_stderr --partial "manual set to true"
    assert_stderr --partial "[manual] have been enabled"
    rune -0 cscli console enable manual --debug
    assert_stderr --partial "manual already set to true"
    assert_stderr --partial "[manual] have been enabled"
    rune -0 cscli console enable manual context --debug
    assert_stderr --partial "context set to true"
    assert_stderr --partial "[manual context] have been enabled"
    rune -0 cscli console enable --all --debug
    assert_stderr --partial "custom already set to true"
    assert_stderr --partial "manual already set to true"
    assert_stderr --partial "tainted already set to true"
    assert_stderr --partial "context already set to true"
    assert_stderr --partial "console_management set to true"
    assert_stderr --partial "All features have been enabled successfully"
    rune -1 cscli console enable tralala
    assert_stderr --partial "unknown flag tralala"
}

@test "cscli console disable" {
    rune -0 cscli console disable tainted --debug
    assert_stderr --partial "tainted set to false"
    assert_stderr --partial "[tainted] have been disabled"
    rune -0 cscli console disable tainted --debug
    assert_stderr --partial "tainted already set to false"
    assert_stderr --partial "[tainted] have been disabled"
    rune -0 cscli console disable tainted custom --debug
    assert_stderr --partial "custom set to false"
    assert_stderr --partial "[tainted custom] have been disabled"
    rune -0 cscli console disable --all --debug
    assert_stderr --partial "custom already set to false"
    assert_stderr --partial "manual already set to false"
    assert_stderr --partial "tainted already set to false"
    assert_stderr --partial "context already set to false"
    assert_stderr --partial "console_management already set to false"
    assert_stderr --partial "All features have been disabled"
    rune -1 cscli console disable tralala
    assert_stderr --partial "unknown flag tralala"
}
