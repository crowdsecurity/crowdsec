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

@test "we have exactly one machine" {
    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated]' <(output)
    assert_output '[1,"githubciXXXXXXXXXXXXXXXXXXXXXXXX",true]'
}

@test "don't overwrite local credentials by default" {
    rune -1 cscli machines add local -a
    assert_stderr --partial 'already exists: please remove it, use "--force" or specify a different file with "-f"'
    rune -0 cscli machines add local -a --force
    assert_stderr --partial "Machine 'local' successfully added to the local API."
}

@test "passwords have a size limit" {
    rune -1 cscli machines add local --password "$(printf '%73s' '' | tr ' ' x)"
    assert_stderr --partial "password too long (max 72 characters)"
}

@test "add a new machine and delete it" {
    rune -0 cscli machines add -a -f /dev/null CiTestMachine -o human
    assert_stderr --partial "Machine 'CiTestMachine' successfully added to the local API"
    assert_stderr --partial "API credentials written to '/dev/null'"

    # we now have two machines
    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[-1].machineId, .[0].isValidated]' <(output)
    assert_output '[2,"CiTestMachine",true]'

    # delete the test machine
    rune -0 cscli machines delete CiTestMachine -o human
    assert_stderr --partial "machine 'CiTestMachine' deleted successfully"

    # we now have one machine again
    rune -0 cscli machines list -o json
    rune -0 jq '. | length' <(output)
    assert_output 1
}

@test "delete non-existent machine" {
    # this is not a fatal error, won't halt a script with -e
    rune -0 cscli machines delete something
    assert_stderr --partial "unable to delete machine: 'something' does not exist"
    rune -0 cscli machines delete something --ignore-missing
    refute_stderr
}

@test "machines [delete|inspect] has autocompletion" {
    rune -0 cscli machines add -a -f /dev/null foo1
    rune -0 cscli machines add -a -f /dev/null foo2
    rune -0 cscli machines add -a -f /dev/null bar
    rune -0 cscli machines add -a -f /dev/null baz
    rune -0 cscli __complete machines delete 'foo'
    assert_line --index 0 'foo1'
    assert_line --index 1 'foo2'
    refute_line 'bar'
    refute_line 'baz'
    rune -0 cscli __complete machines inspect 'foo'
    assert_line --index 0 'foo1'
    assert_line --index 1 'foo2'
    refute_line 'bar'
    refute_line 'baz'
}

@test "heartbeat is initially null" {
    rune -0 cscli machines add foo --auto --file /dev/null
    rune -0 cscli machines list -o json
    rune -0 yq '.[] | select(.machineId == "foo") | .last_heartbeat' <(output)
    assert_output null
}

@test "register, validate and then remove a machine" {
    rune -0 cscli lapi register --machine CiTestMachineRegister -f /dev/null -o human
    assert_stderr --partial "Successfully registered to Local API (LAPI)"
    assert_stderr --partial "Local API credentials written to '/dev/null'"

    # the machine is not validated yet
    rune -0 cscli machines list -o json
    rune -0 jq '.[-1].isValidated' <(output)
    assert_output 'null'

    # validate the machine
    rune -0 cscli machines validate CiTestMachineRegister -o human
    assert_stderr --partial "machine 'CiTestMachineRegister' validated successfully"

    # the machine is now validated
    rune -0 cscli machines list -o json
    rune -0 jq '.[-1].isValidated' <(output)
    assert_output 'true'

    # delete the test machine again
    rune -0 cscli machines delete CiTestMachineRegister -o human
    assert_stderr --partial "machine 'CiTestMachineRegister' deleted successfully"

    # we now have one machine, again
    rune -0 cscli machines list -o json
    rune -0 jq '. | length' <(output)
    assert_output 1
}

@test "cscli machines prune" {
    rune -0 cscli metrics

    # if the fixture has been created some time ago,
    # the machines may be old enough to trigger a user prompt.
    # make sure the prune duration is high enough.
    rune -0 cscli machines prune --duration 1000000h
    assert_output 'No machines to prune.'

    rune -0 cscli machines list -o json
    rune -0 jq -r '.[-1].machineId' <(output)
    rune -0 cscli machines delete "$output"

    rune -0 cscli machines prune
    assert_output 'No machines to prune.'
}
