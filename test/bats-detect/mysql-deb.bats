#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    # debian: mysql-community-server
    # ubuntu: mysql-server
    deb-remove mysql-server mysql-community-server
}

setup() {
    if ! command -v dpkg >/dev/null; then
        skip 'not a debian-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    if apt-cache search --names-only "^mysql-server$"; then
        skip "mysql-server package not available"
    fi
}

#----------

@test "mysql: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'mysql-systemd'
}

@test "mysql: install" {
    # ubuntu comes with mysql, debian does not
    if apt-cache search --names-only "^mysql-server$"; then
        # package not available, install the repo
        filename="mysql-apt-config_0.8.23-1_all.deb"
        run -0 curl -1sSLf "https://dev.mysql.com/get/${filename}" -o "${CACHEDIR}/${filename}"
        # XXX md5 c2b410031867dc7c966ca5b1aa0c72aa
        run -0 sudo dpkg --install "${CACHEDIR}/${filename}"
        run -0 deb-update
        # XXX this hangs
        run -0 deb-install mysql-community-server
    else
    	run -0 deb-install mysql-server
    fi
    run -0 sudo systemctl enable mysql.service
}

@test "mysql: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'mysql-systemd'
}

@test "mysql: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
