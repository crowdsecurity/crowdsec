#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

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

    cscli collections install crowdsecurity/sshd --error
    cscli parsers install crowdsecurity/syslog-logs --error
    cscli parsers install crowdsecurity/dateparse-enrich --error

    ./instance-crowdsec start
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "-type and -dsn are required together" {
    rune -1 "${CROWDSEC}" -no-api -type syslog
    assert_stderr --partial "-type requires a -dsn argument"
    rune -1 "${CROWDSEC}" -no-api -dsn file:///dev/fd/0
    assert_stderr --partial "-dsn requires a -type argument"
}

@test "the one-shot mode works" {
    rune -0 "${CROWDSEC}" -dsn file://<(fake_log) -type syslog -no-api
    refute_output
    assert_stderr --partial "single file mode : log_media=stdout daemonize=false"
    assert_stderr --regexp "Adding file .* to filelist"
    assert_stderr --regexp "reading .* at once"
    assert_stderr --regexp "Acquisition is finished, shutting down"
    assert_stderr --regexp "Killing parser routines"
    assert_stderr --regexp "Bucket routine exiting"
    assert_stderr --regexp "crowdsec shutdown"
}

@test "we have one decision" {
    rune -0 cscli decisions list -o json
    rune -0 jq '. | length' <(output)
    assert_output 1
}

@test "1.1.1.172 has been banned" {
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.172 has been banned (range/contained: -r 1.1.1.0/24 --contained)" {
    rune -0 cscli decisions list -r 1.1.1.0/24 --contained -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.172 has not been banned (range/NOT-contained: -r 1.1.2.0/24)" {
    rune -0 cscli decisions list -r 1.1.2.0/24 -o json
    assert_json '[]'
}

@test "1.1.1.172 has been banned (exact: -i 1.1.1.172)" {
    rune -0 cscli decisions list -i 1.1.1.172 -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.173 has not been banned (exact: -i 1.1.1.173)" {
    rune -0 cscli decisions list -i 1.1.1.173 -o json
    assert_json '[]'
}
