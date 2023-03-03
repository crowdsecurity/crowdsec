#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove odoo
}

setup() {
    if ! command -v dnf >/dev/null; then
        skip 'not a redhat-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    skip 'WIP (https://bytemeta.vip/repo/odoo/odoo/issues/95168)'
    ./instance-data load
}

#----------

@test "odoo: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'odoo-systemd'
}

@test "odoo: install" {
    run -0 sudo dnf config-manager --add-repo=https://nightly.odoo.com/15.0/nightly/rpm/odoo.repo
    run -0 rpm-install odoo
    run -0 sudo systemctl enable odoo
}

@test "odoo: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'odoo-systemd'
}

@test "odoo: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
