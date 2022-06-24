#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    [ -n "${PACKAGE_TESTING}" ] && return

    ./instance-data load

    tempfile=$(TMPDIR="${BATS_FILE_TMPDIR}" mktemp)
    export tempfile

    tempfile2=$(TMPDIR="${BATS_FILE_TMPDIR}" mktemp)
    export tempfile2

    DUMMY_YAML="$(config_yq '.config_paths.notification_dir')/dummy.yaml"

    yq e '
       .group_wait="5s" |
       .group_threshold=2 |
       .output_file=strenv(tempfile) |
       .format="{{.|toJson}}"
       ' -i "${DUMMY_YAML}"

    cat <<-EOT >>"${DUMMY_YAML}"
	---
	type: dummy
	name: dummy_2
	log_level: info
	format: secondfile
	output_file: ${tempfile2}
	EOT

    yq e '
       .notifications=["dummy_default","dummy_2"] |
       .filters=["Alert.GetScope() == \"Ip\""]
       ' -i "$(config_yq '.api.server.profiles_path')"

    yq e '
       .plugin_config.user="" |
       .plugin_config.group=""
       ' -i "${CONFIG_YAML}"

    ./instance-crowdsec start
}

teardown_file() {
    load "../lib/teardown_file.sh"
    rm -f "${tempfile}" "${tempfile2}"
}

setup() {
    [ -n "${PACKAGE_TESTING}" ] && skip
    load "../lib/setup.sh"
}

#----------

@test "${FILE} add two bans" {
    sleep 1
    run -0 cscli decisions add --ip 1.2.3.4 --duration 30s
    assert_output --partial 'Decision successfully added'

    run -0 cscli decisions add --ip 1.2.3.5 --duration 30s
    assert_output --partial 'Decision successfully added'
    sleep 2
}

@test "${FILE} expected 1 notification" {
    run -0 cat "${tempfile}"
    assert_output --partial 1.2.3.4
    assert_output --partial 1.2.3.5
}

@test "${FILE} second notification works too" {
    run -0 cat "${tempfile2}"
    assert_output --partial secondfile
}
