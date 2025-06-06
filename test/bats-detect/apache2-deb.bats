#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove apache2
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

@test "apache2: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'apache2-systemd-deb'
    refute_line 'apache2-systemd-rpm'
}

@test "apache2: install" {
    run -0 deb-install apache2
    run -0 sudo systemctl enable apache2.service
}

@test "apache2: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'apache2-systemd-deb'
    refute_line 'apache2-systemd-rpm'
}

@test "apache2: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
