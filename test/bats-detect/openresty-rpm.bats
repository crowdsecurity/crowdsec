#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    rpm-remove openresty
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

@test "openresty: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'openresty-systemd'
}

@test "openresty: install" {
    run -0 rpm-install redhat-lsb-core
    if [[ "$(lsb_release -is)" == "Fedora" ]]; then
        run -0 sudo curl -1sSLf "https://openresty.org/package/fedora/openresty.repo" -o "/etc/yum.repos.d/openresty.repo"
    elif [[ "$(lsb_release -is)" == "CentOS" ]]; then
        run -0 sudo curl -1sSLf "https://openresty.org/package/centos/openresty.repo" -o "/etc/yum.repos.d/openresty.repo"
    fi
    run -0 sudo dnf check-update
    run -0 rpm-install openresty
    run -0 sudo systemctl enable openresty.service
}

@test "openresty: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'openresty-systemd'
}

@test "openresty: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
