#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

fake_log() {
    for _ in $(seq 1 10); do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.174 port 35424'
    done
}

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    cscli decisions delete --all
}

#----------

@test "$FILE we have one decision" {
    run -0 cscli simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run -0 cscli decisions list -o json
    run -0 jq '. | length' <(output)
    assert_output 1
}

@test "$FILE 1.1.1.174 has been banned (exact)" {
    run -0 cscli simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run -0 cscli decisions list -o json
    run -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.174'
}

@test "$FILE decision has simulated == false (exact)" {
    run -0 cscli simulation disable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run -0 cscli decisions list -o json
    run -0 jq '.[].decisions[0].simulated' <(output)
    assert_output 'false'
}

@test "$FILE simulated scenario, listing non-simulated: expect no decision" {
    run -0 cscli simulation enable crowdsecurity/ssh-bf
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run -0 cscli decisions list --no-simu -o json
    assert_output 'null'
}

@test "$FILE global simulation, listing non-simulated: expect no decision" {
    run -0 cscli simulation disable crowdsecurity/ssh-bf
    run -0 cscli simulation enable --global
    fake_log | "${CROWDSEC}" -dsn file:///dev/fd/0 -type syslog -no-api
    run -0 cscli decisions list --no-simu -o json
    assert_output 'null'
}
