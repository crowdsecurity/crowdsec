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
    cscli decisions delete --all
}

#----------

@test "we have one decision" {
    rune -0 cscli simulation disable --global
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list -o json
    rune -0 jq '. | length' <(output)
    assert_output 1
}

@test "1.1.1.174 has been banned (exact)" {
    rune -0 cscli simulation disable --global
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.174'
}

@test "decision has simulated == false (exact)" {
    rune -0 cscli simulation disable --global
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list -o json
    rune -0 jq '.[].decisions[0].simulated' <(output)
    assert_output 'false'
}

@test "simulated scenario, listing non-simulated: expect no decision" {
    rune -0 cscli simulation enable crowdsecurity/ssh-bf
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list --no-simu -o json
    assert_json '[]'
}

@test "simulated local scenario: expect no decision" {
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    rune -0 mkdir -p "$CONFIG_DIR"/scenarios
    # replace an installed scenario with a local version
    rune -0 cp -r "$HUB_DIR"/scenarios/crowdsecurity/ssh-bf.yaml "$CONFIG_DIR"/scenarios/ssh-bf2.yaml
    rune -0 cscli scenarios remove crowdsecurity/ssh-bf --force --purge
    rune -0 cscli simulation enable crowdsecurity/ssh-bf
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list --no-simu -o json
    assert_json '[]'
}

@test "global simulation, listing non-simulated: expect no decision" {
    rune -0 cscli simulation disable crowdsecurity/ssh-bf
    rune -0 cscli simulation enable --global
    fake_log | "$CROWDSEC" -dsn file:///dev/fd/0 -type syslog -no-api
    rune -0 cscli decisions list --no-simu -o json
    assert_json '[]'
}
