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
    load "../lib/bats-file/load.bash"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "can list machines as regular user" {
    rune -0 cscli machines list
}

@test "we have exactly one machine" {
    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated]' <(output)
    assert_output '[1,"githubciXXXXXXXXXXXXXXXXXXXXXXXX",true]'
}

@test "adding a machines prints credentials (to stdout by default)" {
    rune -0 cscli machines add testmachine --password testpassword
    rune -0 yq -o json . <(output)
    assert_json '{login: "testmachine", password: "testpassword", url: "http://127.0.0.1:8080"}'

    rune -1 cscli machines add testmachine --password testpassword
    assert_stderr --partial "unable to create machine: user 'testmachine': user already exist"

    # the "-" name as stdout still works
    rune -0 cscli machines add testmachine2 --password testpassword -f -
    rune -0 yq -o json . <(output)
    assert_json '{login: "testmachine2", password: "testpassword", url: "http://127.0.0.1:8080"}'

    tempfile="${BATS_TEST_TMPDIR}/testmachine.yml"
    rune -0 cscli machines add testmachine3 --password testpassword -f "${tempfile}"
    assert_stderr --partial "API credentials dumped to '${tempfile}'"
    rune -0 yq -o json . < "$tempfile"
    assert_json '{login: "testmachine3", password: "testpassword", url: "http://127.0.0.1:8080"}'
    assert_file_permission 600 "$tempfile"
}

@test "add a new machine and delete it" {
    rune -0 cscli machines add -a -f /dev/null CiTestMachine -o human
    assert_stderr --partial "Machine 'CiTestMachine' successfully added to the local API"
    assert_stderr --partial "API credentials dumped to '/dev/null'"

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
    assert_stderr --partial "Local API credentials dumped to '/dev/null'"

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
