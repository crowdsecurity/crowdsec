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

@test "cscli metrics show bouncers" {
    # there are no bouncers, so no metrics yet
    rune -0 cscli metrics show bouncers
    refute_output
}

@test "rc usage metrics (empty payload)" {
    # a registered bouncer can send metrics for the lapi and console
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(cat <<-EOT
	remediation_components: []
	log_processors: []
	EOT
    )

    rune -22 curl-with-key '/v1/usage-metrics' --data "$(echo "$payload" | yq -o j)" -X POST
    assert_stderr 'curl: (22) The requested URL returned error: 404'
    refute_output
}
