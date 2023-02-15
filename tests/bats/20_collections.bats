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
    run -0 --separate-stderr cscli collections list -o json
    run -0 jq '.collections | length' <(output)
    assert_output 2
}

@test "can install a collection (as a regular user) and remove it" {
    # collection is not installed
    run -0 --separate-stderr cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/mysql"

    # we install it
    run -0 --separate-stderr cscli collections install crowdsecurity/mysql -o human
    assert_stderr --partial "Enabled crowdsecurity/mysql"

    # it has been installed
    run -0 --separate-stderr cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    assert_line "crowdsecurity/mysql"

    # we install it
    run -0 cscli collections remove crowdsecurity/mysql -o human
    assert_output --partial "Removed symlink [crowdsecurity/mysql]"

    # it has been removed
    run -0 --separate-stderr cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/mysql"
}

@test "must use --force to remove a collection that belongs to another, which becomes tainted" {
    # we expect no error since we may have multiple collections, some removed and some not
    run -0 --separate-stderr cscli collections remove crowdsecurity/sshd
    assert_stderr --partial "crowdsecurity/sshd belongs to other collections"
    assert_stderr --partial "[crowdsecurity/linux]"

    run -0 --separate-stderr cscli collections remove crowdsecurity/sshd --force
    assert_stderr --partial "Removed symlink [crowdsecurity/sshd]"
    run -0 --separate-stderr cscli collections inspect crowdsecurity/linux -o json
    run -0 jq -r '.tainted' <(output)
    assert_output "true"
}

@test "can remove a collection" {
    run -0 cscli collections remove crowdsecurity/linux
    assert_output --partial "Removed"
    assert_output --regexp   ".*for the new configuration to be effective."
    run -0 cscli collections inspect crowdsecurity/linux -o human
    assert_line 'installed: false'
}

@test "collections delete is an alias for collections remove" {
    run -0 cscli collections delete crowdsecurity/linux
    assert_output --partial "Removed"
    assert_output --regexp   ".*for the new configuration to be effective."
}

@test "removing a collection that does not exist is noop" {
    run -0 cscli collections remove crowdsecurity/apache2
    refute_output --partial "Removed"
    assert_output --regexp   ".*for the new configuration to be effective."
}

@test "can remove a removed collection" {
    run -0 cscli collections install crowdsecurity/mysql
    run -0 cscli collections remove crowdsecurity/mysql
    assert_output --partial "Removed"
    run -0 cscli collections remove crowdsecurity/mysql
    refute_output --partial "Removed"
}

@test "can remove all collections" {
    # we may have this too, from package installs
    run cscli parsers delete crowdsecurity/whitelists
    run -0 cscli collections remove --all
    assert_output --partial "Removed symlink [crowdsecurity/sshd]"
    assert_output --partial "Removed symlink [crowdsecurity/linux]"
    run -0 --separate-stderr cscli hub list -o json
    assert_json '{collections:[],parsers:[],postoverflows:[],scenarios:[]}'
    run -0 cscli collections remove --all
    assert_output --partial 'Disabled 0 items'
}

# TODO test download-only
