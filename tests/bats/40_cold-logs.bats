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
    ./instance-crowdsec start
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api 2>/dev/null
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "we have one decision" {
    run -0 cscli decisions list -o json
    run -0 jq '. | length' <(output)
    assert_output 1
}

@test "1.1.1.172 has been banned" {
    run -0 cscli decisions list -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.172 has been banned (range/contained: -r 1.1.1.0/24 --contained)" {
    run -0 cscli decisions list -r 1.1.1.0/24 --contained -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.172 has not been banned (range/NOT-contained: -r 1.1.2.0/24)" {
    run -0 cscli decisions list -r 1.1.2.0/24 -o json
    assert_output 'null'
}

@test "1.1.1.172 has been banned (exact: -i 1.1.1.172)" {
    run -0 cscli decisions list -i 1.1.1.172 -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}

@test "1.1.1.173 has not been banned (exact: -i 1.1.1.173)" {
    run -0 cscli decisions list -i 1.1.1.173 -o json
    assert_output 'null'
}
