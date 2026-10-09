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
    ./instance-crowdsec start
}

teardown() {
    cd "$TEST_DIR" || exit 1
    ./instance-crowdsec stop
}

#----------

@test "cscli notifications <unknown command>" {
    rune -1 cscli notifications foobar
    assert_output --partial "Usage:"
    assert_stderr --partial 'unknown command "foobar" for "cscli notifications"'
}

@test "cscli notifications list" {
    rune -0 cscli notifications list
    assert_output --partial "Name"
    assert_output --partial "Type"
    assert_output --partial "Profile name"
}

@test "cscli notifications must be run from lapi" {
    config_disable_lapi
    rune -1 cscli notifications list
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}

@test "cscli notifications: profiles can use macros" {
    rune -0 config_get '.api.server.profiles_path'
    profiles="$output"
    cat <<-EOT >"$profiles"
	name: macro_profile
	filters:
	 - IsIp()
	decisions:
	 - type: ban
	   duration: 4h
	on_success: break
	EOT

    rune -1 cscli notifications list
    assert_stderr --partial "unknown name IsIp"

    macro_dir="$(config_get '.config_paths.config_dir')/macros"
    mkdir -p "$macro_dir"
    echo 'macros: {IsIp: Alert.GetScope() == "Ip"}' > "$macro_dir/test.yaml"
    rune -0 cscli notifications list
}
