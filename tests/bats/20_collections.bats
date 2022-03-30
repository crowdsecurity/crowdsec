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

@test "$FILE we can list collections" {
    run -0 cscli collections list
}

@test "$FILE there are 2 collections (linux and sshd)" {
    run -0 cscli collections list -o json
    run -0 jq '.collections | length' <(output)
    assert_output 2
}

@test "$FILE can install a collection (as a regular user) and remove it" {
    run -0 cscli collections install crowdsecurity/mysql -o human
    assert_output --partial "Enabled crowdsecurity/mysql"
    run -0 cscli collections list -o json
    run -0 jq '.collections | length' <(output)
    assert_output 3
    run -0 cscli collections remove crowdsecurity/mysql -o human
    assert_output --partial "Removed symlink [crowdsecurity/mysql]"
}

@test "$FILE cannot remove a collection twice" {
    run -0 cscli collections install crowdsecurity/mysql -o human
    run -0 --separate-stderr cscli collections remove crowdsecurity/mysql
    run -1 --separate-stderr cscli collections remove crowdsecurity/mysql -o json
    run -0 jq -r '.level' <(stderr)
    assert_output 'fatal'
    run -0 jq -r '.msg' <(stderr)
    assert_output --partial "unable to disable crowdsecurity/mysql"
    assert_output --partial "doesn't exist"
}
