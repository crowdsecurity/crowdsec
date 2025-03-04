#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    rpm-remove pure-ftpd
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

@test "pureftpd: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'pureftpd-systemd'
}

@test "pureftpd: install" {
    run -0 rpm-install pure-ftpd
    run -0 sudo systemctl enable pure-ftpd.service
}

@test "pureftpd: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'pureftpd-systemd'
}

@test "pureftpd: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
