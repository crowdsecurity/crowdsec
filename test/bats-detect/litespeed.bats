#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    deb-remove openlitespeed
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    skip 'WIP'
    ./instance-data load
}

#----------

@test "openlitespeed: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'litespeed-systemd'
}

@test "openlitespeed: install" {
    run -0 sudo "${TESTDATA}/enable_lst_debian_repo.sh"
    run -0 deb-update
    run -0 deb-install openlitespeed
    # run -0 sudo systemctl enable XXX TODO
}

@test "litespeed: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'litespeed-systemd'
}

@test "litespeed: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
