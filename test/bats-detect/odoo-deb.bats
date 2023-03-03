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
    if ! command -v dpkg >/dev/null; then
        skip 'not a debian-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

#----------

@test "odoo: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'odoo-systemd'
}

@test "odoo: install" {
    run -0 deb-install debian-keyring debian-archive-keyring apt-transport-https
    run -0 curl -1sSLf https://nightly.odoo.com/odoo.key
    run -0 sudo gpg --yes --dearmor -o /usr/share/keyrings/odoo-keyring.gpg < <(output)
    run -0 sudo tee <<< "deb [signed-by=/usr/share/keyrings/odoo-keyring.gpg] https://nightly.odoo.com/15.0/nightly/deb/ ./" /etc/apt/sources.list.d/odoo.list >/dev/null
    run -0 deb-update
    run -0 deb-install odoo
#    run -0 sudo systemctl enable caddy.service
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
