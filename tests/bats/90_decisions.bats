#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh" >&3 2>&1
}

teardown_file() {
    load "../lib/teardown_file.sh" >&3 2>&1
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

declare stderr

#----------

@test "$FILE 'decisions add' requires parameters" {
    run -1 --separate-stderr cscli decisions add
    assert_line "Usage:"
    run echo "$stderr"
    assert_output --partial "Missing arguments, a value is required (--ip, --range or --scope and --value)"

    run -1 --separate-stderr cscli decisions add -o json
    run echo "$stderr"
    run -0 jq -c '[ .level, .msg]' <(output)
    assert_output '["fatal","Missing arguments, a value is required (--ip, --range or --scope and --value)"]'
}

