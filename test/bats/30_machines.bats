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

    rune -0 cscli machines prune
    assert_output 'No machines to prune.'

    rune -0 cscli machines list -o json
    rune -0 jq -r '.[-1].machineId' <(output)
    rune -0 cscli machines delete "$output"

    rune -0 cscli machines prune
    assert_output 'No machines to prune.'
}

@test "usage metrics" {
    # a registered log processor can send metrics for the console
    token=$(lp_login)
    usage_metrics="http://localhost:8080/v1/usage-metrics"

    payload=$(cat <<-EOT
	remediation_components: []
	log_processors:
	    - version: "v1.0"
	      feature_flags:
	          - marshmallows
	      meta:
	        window_size_seconds: 600
	        utc_startup_timestamp: 1707399316
	        utc_now_timestamp: 1707485349
	      os:
	        name: CentOS
	        version: "8"
	      metrics:
	        - name: logs_parsed
	          value: 5000
	          unit: count
	          labels: {}
	      console_options:
	        - share_context
	      datasources:
	        syslog: 1
	        file: 4
	EOT
    )

    echo -e "$payload" >/tmp/bbb
    rune -0 curl -f -sS -H "Authorization: Bearer ${token}" -X POST "$usage_metrics" --data "$(echo "$payload" | yq -o j)"
    refute_output
}
