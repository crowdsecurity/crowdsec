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

@test "can list machines as regular user" {
    run -0 cscli machines list
}

@test "we have exactly one machine" {
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated]' <(output)
    assert_output '[1,"githubciXXXXXXXXXXXXXXXXXXXXXXXX",true]'
}

@test "add a new machine and delete it" {
    run -0 cscli machines add -a -f /dev/null CiTestMachine -o human
    assert_output --partial "Machine 'CiTestMachine' successfully added to the local API"
    assert_output --partial "API credentials dumped to '/dev/null'"

    # we now have two machines
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq -c '[. | length, .[-1].machineId, .[0].isValidated]' <(output)
    assert_output '[2,"CiTestMachine",true]'

    # delete the test machine
    run -0 cscli machines delete CiTestMachine -o human
    assert_output --partial "machine 'CiTestMachine' deleted successfully"

    # we now have one machine again
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq '. | length' <(output)
    assert_output 1
}

@test "register, validate and then remove a machine" {
    run -0 cscli lapi register --machine CiTestMachineRegister -f /dev/null -o human
    assert_output --partial "Successfully registered to Local API (LAPI)"
    assert_output --partial "Local API credentials dumped to '/dev/null'"

    # the machine is not validated yet
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq '.[-1].isValidated' <(output)
    assert_output 'null'

    # validate the machine
    run -0 cscli machines validate CiTestMachineRegister -o human
    assert_output --partial "machine 'CiTestMachineRegister' validated successfully"

    # the machine is now validated
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq '.[-1].isValidated' <(output)
    assert_output 'true'

    # delete the test machine again
    run -0 cscli machines delete CiTestMachineRegister -o human
    assert_output --partial "machine 'CiTestMachineRegister' deleted successfully"

    # we now have one machine, again
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq '. | length' <(output)
    assert_output 1
}
