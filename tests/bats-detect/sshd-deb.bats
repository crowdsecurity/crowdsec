#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    # don't remove ssh here, we assume it's needed
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

@test "sshd: detect unit (fail)" {
    run -0 sudo systemctl mask ssh.service
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'sshd-systemd'
}

@test "sshd: install" {
#    run -0 deb-install openssh-server
    run -0 sudo systemctl unmask ssh.service
    run -0 sudo systemctl enable ssh.service
}

@test "sshd: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'sshd-systemd'
}

@test "sshd: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
