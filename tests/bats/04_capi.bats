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
    run -0 cscli capi register --schmilblick githubciXXXXXXXXXXXXXXXXXXXXXXXX
    run -0 cscli capi status
    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial " on https://api.crowdsec.net/"
    assert_output --partial "You can successfully interact with Central API (CAPI)"
}

@test "cscli alerts list: receive a community pull when capi is enabled" {
    sleep 2
    ./instance-crowdsec start
    for ((i=0; i<15; i++)); do
        sleep 2
        [[ $(cscli alerts list -a -o json 2>/dev/null || cscli alerts list -o json) != "null" ]] && break
    done

    run --separate-stderr cscli alerts list -a -o json
    if [[ "${status}" -ne 0 ]]; then
        run --separate-stderr cscli alerts list -o json
    fi
    run -0 jq -r '. | length' <(output)
    refute_output 0
}

@test "we have exactly one machine, localhost" {
    run -0 --separate-stderr cscli machines list -o json
    run -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated, .[0].ipAddress]' <(output)
    assert_output '[1,"githubciXXXXXXXXXXXXXXXXXXXXXXXX",true,"127.0.0.1"]'
}

@test "no agent: capi status should be ok" {
    ./instance-crowdsec stop
    config_disable_agent
    ./instance-crowdsec start
    run -0 --separate-stderr cscli capi status
    assert_stderr --partial "You can successfully interact with Central API (CAPI)"
}

@test "cscli capi status: fails without credentials" {
    ONLINE_API_CREDENTIALS_YAML="$(config_get '.api.server.online_client.credentials_path')"
    rm "${ONLINE_API_CREDENTIALS_YAML}"
    run -1 --separate-stderr cscli capi status
    assert_stderr --partial "Local API is disabled, please run this command on the local API machine: loading online client credentials: failed to read api server credentials configuration file '${ONLINE_API_CREDENTIALS_YAML}': open ${ONLINE_API_CREDENTIALS_YAML}: no such file or directory"
}
