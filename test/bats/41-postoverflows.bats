#!/usr/bin/env bats

set -u

fake_log() {
    for _ in $(seq 1 6); do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424'
    done
}

setup_file() {
    load "../lib/setup_file.sh"
    # we reset config and data, and only run the daemon once for all the tests in this file
    ./instance-data load

    cscli collections install crowdsecurity/sshd --error >/dev/null
    cscli parsers install crowdsecurity/syslog-logs --error >/dev/null
    cscli parsers install crowdsecurity/dateparse-enrich --error >/dev/null

    ./instance-crowdsec start
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "apply postoverflow" {
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    mkdir -p "$CONFIG_DIR"/postoverflows/s01-whitelist
    cat > "$CONFIG_DIR"/postoverflows/s01-whitelist/po-test.yaml <<-EOT
	name: crowdsecurity/po-test
	description: "foo"
	whitelist:
	  reason: "foo"
	  expression: 
	    - "evt.Overflow.Alert.Source.IP == '1.1.1.172'"
	EOT

    rune -0 "$CROWDSEC" -dsn file://<(fake_log) -type syslog -no-api
    refute_output
    assert_stderr --regexp "Adding file .* to filelist"
    assert_stderr --regexp "reading .* at once"
    assert_stderr --partial "Ban for 1.1.1.172 whitelisted"
    assert_stderr --regexp "Acquisition is finished, shutting down"
    assert_stderr --regexp "Killing parser routines"
    assert_stderr --regexp "Bucket routine exiting"
    assert_stderr --regexp "crowdsec shutdown"
}

@test "we have no decision" {
    rune -0 cscli decisions list -o json
    rune -0 jq '. | length' <(output)
    assert_output 0
}
