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
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli - connects from existing machine with socket" {
    sockdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    mkdir -p "${sockdir}"
    export socket="${sockdir}/crowdsec_api.sock"

    config_set ".api.server.listen_socket=strenv(socket)"

    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "${LOCAL_API_CREDENTIALS}" ".url=strenv(socket)"

    ./instance-crowdsec start
    rune -0 cscli lapi status
    # XXX not what we want to show in the logs
    assert_stderr --regexp "Trying to authenticate with username .* on $socket"
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"
}

@test "crowdsec - listen on both socket and TCP" {
    sockdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    mkdir -p "${sockdir}"
    export socket="${sockdir}/crowdsec_api.sock"

    config_set ".api.server.listen_socket=strenv(socket)"

    ./instance-crowdsec start

    rune -0 cscli lapi status
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"

    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "${LOCAL_API_CREDENTIALS}" ".url=strenv(socket)"

    rune -0 cscli lapi status
    assert_stderr --regexp "Trying to authenticate with username .* on $socket"
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli - authenticate new machine with socket" {
    # verify that if a listen_uri and a socket are set, the socket is used
    # by default when creating a local machine.

    sockdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    mkdir -p "${sockdir}"
    export socket="${sockdir}/crowdsec_api.sock"

    config_set ".api.server.listen_socket=strenv(socket)"
    rune -0 cscli machines delete "$(cscli machines list -o json | jq -r '.[].machineId')"

    # this one should be using the socket
    rune -0 cscli machines add --auto --force

    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    using=$(config_get "${LOCAL_API_CREDENTIALS}" ".url")

    assert [ "$using" = "$socket" ]

    # disable the agent because it counts as a first authentication
    config_disable_agent
    ./instance-crowdsec start

    # the machine does not have an IP yet

    rune -0 cscli machines list -o json
    rune -0 jq -r '.[].ipAddress' <(output)
    assert_output null

    # upon first authentication, it's assigned to localhost

    rune -0 cscli lapi status

    rune -0 cscli machines list -o json
    rune -0 jq -r '.[].ipAddress' <(output)
    assert_output 127.0.0.1
}
