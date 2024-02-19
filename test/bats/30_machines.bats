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
    rune -1 cscli machines add local -a -o json
    rune -0 jq -r '.msg' <(stderr)
    assert_output --partial 'already exists: please remove it, use "--force" or specify a different file with "-f"'
    rune -0 cscli machines add local -a --force
    assert_output --partial "Machine 'local' successfully added to the local API."
}

@test "add a new machine and delete it" {
    rune -0 cscli machines add -a -f /dev/null CiTestMachine -o human
    assert_output --partial "Machine 'CiTestMachine' successfully added to the local API"
    assert_output --partial "API credentials written to '/dev/null'"

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
