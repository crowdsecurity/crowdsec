#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove proxmox-ve
}

setup() {
    if ! command -v dpkg >/dev/null; then
        skip 'not a debian-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load

    . /etc/os-release
    case "$VERSION_CODENAME" in
        bullseye | buster | jessie | squeeze | stretch | wheezy)
        skip "the installation does not work"
        ;;
    *)
        skip "unsupported distribution"
        ;;
    esac
    export VERSION_CODENAME
}

#----------

@test "proxmox: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'proxmox-systemd'
}

@test "proxmox: install" {
    run -0 deb-install debian-keyring debian-archive-keyring apt-transport-https
    run -0 sudo curl -1sSLf http://download.proxmox.com/debian/proxmox-ve-release-6.x.gpg -o /etc/apt/trusted.gpg.d/proxmox-ve-release-6.x.gpg
    run -0 sudo tee <<<"deb http://download.proxmox.com/debian/pve ${VERSION_CODENAME} pve-no-subscription" /etc/apt/sources.list.d/proxmox.list >/dev/null
    run -0 deb-update
    run -0 deb-install proxmox-ve
    run -0 sudo systemctl enable proxmox.service
}

@test "proxmox: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'proxmox-systemd'
}

@test "proxmox: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
