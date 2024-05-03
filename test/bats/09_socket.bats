#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    sockdir=$(TMPDIR="$BATS_FILE_TMPDIR" mktemp -u)
    export sockdir
    mkdir -p "$sockdir"
    socket="$sockdir/crowdsec_api.sock"
    export socket
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    export LOCAL_API_CREDENTIALS
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    config_set ".api.server.listen_socket=strenv(socket)"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli - connects from existing machine with socket" {
    config_set "$LOCAL_API_CREDENTIALS" ".url=strenv(socket)"

    ./instance-crowdsec start

    rune -0 cscli lapi status
    assert_output --regexp "Trying to authenticate with username .* on $socket"
    assert_line "You can successfully interact with Local API (LAPI)"
}

@test "crowdsec - listen on both socket and TCP" {
    ./instance-crowdsec start

    rune -0 cscli lapi status
    assert_output --regexp "Trying to authenticate with username .* on http://127.0.0.1:8080/"
    assert_line "You can successfully interact with Local API (LAPI)"

    config_set "$LOCAL_API_CREDENTIALS" ".url=strenv(socket)"

    rune -0 cscli lapi status
    assert_output --regexp "Trying to authenticate with username .* on $socket"
    assert_line "You can successfully interact with Local API (LAPI)"
}

@test "cscli - authenticate new machine with socket" {
    # verify that if a listen_uri and a socket are set, the socket is used
    # by default when creating a local machine.

    rune -0 cscli machines delete "$(cscli machines list -o json | jq -r '.[].machineId')"

    # this one should be using the socket
    rune -0 cscli machines add --auto --force

    using=$(config_get "$LOCAL_API_CREDENTIALS" ".url")

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

bouncer_http() {
    URI="$1"
    curl -fs -H "X-Api-Key: $API_KEY" "http://localhost:8080$URI"
}

bouncer_socket() {
    URI="$1"
    curl -fs -H "X-Api-Key: $API_KEY" --unix-socket "$socket" "http://localhost$URI"
}

@test "lapi - connects from existing bouncer with socket" {
    ./instance-crowdsec start
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    # the bouncer does not have an IP yet

    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[].ip_address' <(output)
    assert_output ""

    # upon first authentication, it's assigned to localhost

    rune -0 bouncer_socket '/v1/decisions'
    assert_output 'null'
    refute_stderr

    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[].ip_address' <(output)
    assert_output "127.0.0.1"

    # we can still use TCP of course

    rune -0 bouncer_http '/v1/decisions'
    assert_output 'null'
    refute_stderr
}

@test "lapi - listen on socket only" {
    config_set "del(.api.server.listen_uri)"

    mkdir -p "$sockdir"

    # agent is not able to connect right now
    config_disable_agent
    ./instance-crowdsec start

    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    # now we can't

    rune -1 cscli lapi status
    assert_stderr --partial "connection refused"

    rune -7 bouncer_http '/v1/decisions'
    refute_output
    refute_stderr

    # here we can

    config_set "$LOCAL_API_CREDENTIALS" ".url=strenv(socket)"

    rune -0 cscli lapi status

    rune -0 bouncer_socket '/v1/decisions'
    assert_output 'null'
    refute_stderr
}
