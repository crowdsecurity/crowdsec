#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove openresty
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

@test "openresty: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'openresty-systemd'
}

@test "openresty: install" {
    run -0 deb-install debian-keyring debian-archive-keyring apt-transport-https
    run -0 curl -1sSLf 'https://openresty.org/package/pubkey.gpg'
    if [[ "$(lsb_release -is)" == "Ubuntu" ]]; then
        run -0 sudo gpg --yes --dearmor -o /usr/share/keyrings/openresty.gpg < <(output)
        run -0 sudo tee <<< "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/ubuntu $(lsb_release -sc) main" /etc/apt/sources.list.d/openresty.list
    else
        run -0 sudo apt-key add - < <(output)
        run -0 sudo tee <<< "deb http://openresty.org/package/debian $(lsb_release -sc) openresty" /etc/apt/sources.list.d/openresty.list
    fi
    run -0 deb-update
    run -0 deb-install openresty
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
