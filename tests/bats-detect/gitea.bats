#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    skip 'WIP'
    ./instance-data load
}

#----------

@test "gitea: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'gitea-systemd'
}

@test "gitea: install" {
    # https://docs.gitea.io/en-us/install-from-binary/#download
    version=1.16.9
    # don't download twice
    run -0 wget -nc --directory-prefix "$CACHEDIR" "https://dl.gitea.io/gitea/${version}/gitea-${version}-linux-amd64"
}

@test "gitea: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'gitea-systemd'
}

@test "gitea: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
