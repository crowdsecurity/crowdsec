#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "we can list collections" {
    run -0 cscli collections list
}

@test "there are 2 collections (linux and sshd)" {
    run -0 cscli collections list -o json
    run -0 jq '.collections | length' <(output)
    assert_output 2
}

@test "can install a collection (as a regular user) and remove it" {
    # collection is not installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/mysql"

    # we install it
    run -0 cscli collections install crowdsecurity/mysql -o human
    assert_output --partial "Enabled crowdsecurity/mysql"

    # it has been installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    assert_line "crowdsecurity/mysql"

    # we install it
    run -0 cscli collections remove crowdsecurity/mysql -o human
    assert_output --partial "Removed symlink [crowdsecurity/mysql]"

    # it has been removed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/mysql"
}

@test "cannot remove a collection twice" {
    run -0 cscli collections install crowdsecurity/mysql -o human
    run -0 --separate-stderr cscli collections remove crowdsecurity/mysql
    run -1 --separate-stderr cscli collections remove crowdsecurity/mysql -o json
    run -0 jq -r '.level' <(stderr)
    assert_output 'fatal'
    run -0 jq -r '.msg' <(stderr)
    assert_output --partial "unable to disable crowdsecurity/mysql"
    assert_output --partial "doesn't exist"
}

# TODO test download-only
