#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    sudo systemctl stop vsftpd.service 2>/dev/null || :
    deb-remove vsftpd
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

@test "vsftpd: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'vsftpd-systemd'
}

@test "vsftpd: install" {
    run -0 deb-install vsftpd
    run -0 sudo systemctl enable vsftpd.service
}

@test "vsftpd: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'vsftpd-systemd'
}

@test "vsftpd: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
