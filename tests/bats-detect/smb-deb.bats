#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove samba
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

@test "smb: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'smb-systemd'
}

@test "smb: install" {
    run -0 sudo debconf-set-selections <<< "samba-common samba-common/workgroup string WORKGROUP"
    run -0 sudo debconf-set-selections <<< "samba-common samba-common/dhcp boolean true"
    run -0 sudo debconf-set-selections <<< "samba-common samba-common/do_debconf boolean true"
    run -0 deb-install samba
    run -0 sudo systemctl enable smbd.service
}

@test "smb: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'smb-systemd'
}

@test "smb: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
