#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
}

#----------

@test "cscli capi status" {
    config_enable_capi
    rune -0 cscli capi register --schmilblick githubciXXXXXXXXXXXXXXXXXXXXXXXX
    rune -1 cscli capi status
    assert_stderr --partial "no scenarios installed, abort"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli capi status
    assert_stderr --partial "Loaded credentials from"
    assert_stderr --partial "Trying to authenticate with username"
    assert_stderr --partial " on https://api.crowdsec.net/"
    assert_stderr --partial "You can successfully interact with Central API (CAPI)"
}

@test "cscli alerts list: receive a community pull when capi is enabled" {
    sleep 2
    ./instance-crowdsec start
    for ((i=0; i<15; i++)); do
        sleep 2
        [[ $(cscli alerts list -a -o json) != "[]" ]] && break
    done

    rune -0 cscli alerts list -a -o json
    rune -0 jq -r '. | length' <(output)
    refute_output 0
}

@test "we have exactly one machine, localhost" {
    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated, .[0].ipAddress]' <(output)
    assert_json '[1,"githubciXXXXXXXXXXXXXXXXXXXXXXXX",true,"127.0.0.1"]'
}

@test "no agent: capi status should be ok" {
    ./instance-crowdsec stop
    config_disable_agent
    ./instance-crowdsec start
    rune -0 cscli capi status
    assert_stderr --partial "You can successfully interact with Central API (CAPI)"
}

@test "cscli capi status: fails without credentials" {
    ONLINE_API_CREDENTIALS_YAML="$(config_get '.api.server.online_client.credentials_path')"
    rm "${ONLINE_API_CREDENTIALS_YAML}"
    rune -1 cscli capi status
    assert_stderr --partial "failed to load Local API: loading online client credentials: failed to read api server credentials configuration file '${ONLINE_API_CREDENTIALS_YAML}': open ${ONLINE_API_CREDENTIALS_YAML}: no such file or directory"
}

@test "capi register must be run from lapi" {
    config_disable_lapi
    rune -1 cscli capi register --schmilblick githubciXXXXXXXXXXXXXXXXXXXXXXXX
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}
