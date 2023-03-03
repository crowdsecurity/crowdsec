#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

cleanup() {
    command -v dpkg >/dev/null || return 0
    # sudo systemctl stop postgresql.service || :
    # remove the DB to avoid a prompt from postrm
    if [[ -d /var/lib/postgresql ]]; then
        # shellcheck disable=SC2045
        for cluster in $(ls /var/lib/postgresql 2>/dev/null); do
            sudo pg_dropcluster --stop "${cluster}" main
        done
    fi
    deb-remove postgresql $(dpkg -l | grep postgres | awk '{print $2}')
}

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
    cleanup
}

teardown_file() {
    load "../lib/teardown_file.sh"
    cleanup
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

@test "pgsql: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'pgsql-systemd-deb'
}

@test "pgsql: install" {
    run -0 deb-install postgresql
    run -0 sudo systemctl enable postgresql.service
}

@test "pgsql: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'pgsql-systemd-deb'
}

@test "pgsql: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
