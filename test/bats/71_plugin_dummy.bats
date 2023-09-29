#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    is_package_testing && return

    ./instance-data load

    tempfile=$(TMPDIR="${BATS_FILE_TMPDIR}" mktemp)
    export tempfile

    tempfile2=$(TMPDIR="${BATS_FILE_TMPDIR}" mktemp)
    export tempfile2

    DUMMY_YAML="$(config_get '.config_paths.notification_dir')/dummy.yaml"

    config_set "${DUMMY_YAML}" '
       .group_wait="5s" |
       .group_threshold=2 |
       .output_file=strenv(tempfile) |
       .format="{{.|toJson}}"
    '

    cat <<-EOT >>"${DUMMY_YAML}"
	---
	type: dummy
	name: dummy_2
	log_level: info
	format: secondfile
	output_file: ${tempfile2}
	EOT

    config_set "$(config_get '.api.server.profiles_path')" '
       .notifications=["dummy_default","dummy_2"] |
       .filters=["Alert.GetScope() == \"Ip\""]
    '

    config_set '
       .plugin_config.user="" |
       .plugin_config.group=""
    '

    ./instance-crowdsec start
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    is_package_testing && skip
    load "../lib/setup.sh"
}

#----------

@test "add two bans" {
    rune -0 cscli decisions add --ip 1.2.3.4 --duration 30s
    assert_stderr --partial 'Decision successfully added'

    rune -0 cscli decisions add --ip 1.2.3.5 --duration 30s
    assert_stderr --partial 'Decision successfully added'
    sleep 2
}

@test "expected 1 notification" {
    rune -0 cat "${tempfile}"
    assert_output --partial 1.2.3.4
    assert_output --partial 1.2.3.5
}

@test "second notification works too" {
    rune -0 cat "${tempfile2}"
    assert_output --partial secondfile
}
