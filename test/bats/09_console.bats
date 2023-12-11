#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

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
    rune -0 cscli console status
    assert_output --partial "Option Name"
    assert_output --partial "Activated"
    assert_output --partial "Description"
    assert_output --partial "custom"
    assert_output --partial "manual"
    assert_output --partial "tainted"
    assert_output --partial "context"
    assert_output --partial "console_management"
    rune -0 cscli console status -o json
    assert_json - <<- EOT
	{
	"console_management": false,
	"context": false,
	"custom": true,
	"manual": false,
	"tainted": true
	}
	EOT
    rune -0 cscli console status -o raw
    assert_output - <<-EOT
	option,enabled
	manual,false
	custom,true
	tainted,true
	context,false
	console_management,false
	EOT
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
