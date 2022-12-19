#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    rpm-remove caddy
}

setup() {
    if ! command -v dnf >/dev/null; then
        skip 'not a redhat-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

#----------

@test "caddy: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'caddy-systemd'
}

@test "caddy: install" {
    run -0 rpm-install 'dnf-command(copr)'
    run -0 sudo dnf -q -y copr enable @caddy/caddy
    run -0 rpm-install caddy
    run -0 sudo systemctl enable caddy.service
}

@test "caddy: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'caddy-systemd'
}

@test "caddy: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
