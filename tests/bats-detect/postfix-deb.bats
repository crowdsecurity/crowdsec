#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove postfix
}

setup() {
    if ! command -v dpkg >/dev/null; then
        skip 'not a debian-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

#----------

@test "postfix: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'postfix-systemd'
}

@test "postfix: install" {
    run -0 sudo debconf-set-selections <<< "postfix postfix/mailname string hostname.example.com"
    run -0 sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    run -0 deb-install postfix
    run -0 sudo systemctl enable postfix.service
}

@test "postfix: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'postfix-systemd'
}

@test "postfix: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
