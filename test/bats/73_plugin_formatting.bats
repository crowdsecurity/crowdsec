#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    is_package_testing && return

    ./instance-data load

    tempfile=$(TMPDIR="${BATS_FILE_TMPDIR}" mktemp)
    export tempfile

    DUMMY_YAML="$(config_get '.config_paths.notification_dir')/dummy.yaml"

    # we test the template that is suggested in the email notification
    # the $alert is not a shell variable
    # shellcheck disable=SC2016
    config_set "${DUMMY_YAML}" '
       .group_wait="5s" |
       .group_threshold=2 |
       .output_file=strenv(tempfile) |
       .format="<html><body> {{range . -}} {{$alert := . -}} {{range .Decisions -}} <p><a href=\"https://www.whois.com/whois/{{.Value}}\">{{.Value}}</a> will get <b>{{.Type}}</b> for next <b>{{.Duration}}</b> for triggering <b>{{.Scenario}}</b> on machine <b>{{$alert.MachineID}}</b>.</p> <p><a href=\"https://app.crowdsec.net/cti/{{.Value}}\">CrowdSec CTI</a></p> {{end -}} {{end -}} </body></html>"
    '

    config_set "$(config_get '.api.server.profiles_path')" '
       .notifications=["dummy_default"] |
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
    assert_output - <<-EOT
	<html><body> <p><a href="https://www.whois.com/whois/1.2.3.4">1.2.3.4</a> will get <b>ban</b> for next <b>30s</b> for triggering <b>manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX'</b> on machine <b>githubciXXXXXXXXXXXXXXXXXXXXXXXX</b>.</p> <p><a href="https://app.crowdsec.net/cti/1.2.3.4">CrowdSec CTI</a></p> <p><a href="https://www.whois.com/whois/1.2.3.5">1.2.3.5</a> will get <b>ban</b> for next <b>30s</b> for triggering <b>manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX'</b> on machine <b>githubciXXXXXXXXXXXXXXXXXXXXXXXX</b>.</p> <p><a href="https://app.crowdsec.net/cti/1.2.3.5">CrowdSec CTI</a></p> </body></html>
	EOT
}
