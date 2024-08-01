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

@test "cscli capi status: fails without credentials" {
    config_enable_capi
    ONLINE_API_CREDENTIALS_YAML="$(config_get '.api.server.online_client.credentials_path')"
    # bogus values, won't be used
    echo '{"login":"login","password":"password","url":"url"}' > "${ONLINE_API_CREDENTIALS_YAML}"

    config_set "$ONLINE_API_CREDENTIALS_YAML" 'del(.url)'
    rune -1 cscli capi status
    assert_stderr --partial "can't load CAPI credentials from '$ONLINE_API_CREDENTIALS_YAML' (missing url field)"

    config_set "$ONLINE_API_CREDENTIALS_YAML" 'del(.password)'
    rune -1 cscli capi status
    assert_stderr --partial "can't load CAPI credentials from '$ONLINE_API_CREDENTIALS_YAML' (missing password field)"

    config_set "$ONLINE_API_CREDENTIALS_YAML" 'del(.login)'
    rune -1 cscli capi status
    assert_stderr --partial "can't load CAPI credentials from '$ONLINE_API_CREDENTIALS_YAML' (missing login field)"

    rm "${ONLINE_API_CREDENTIALS_YAML}"
    rune -1 cscli capi status
    assert_stderr --partial "failed to load Local API: loading online client credentials: open ${ONLINE_API_CREDENTIALS_YAML}: no such file or directory"

    config_set 'del(.api.server.online_client)'
    rune -1 cscli capi status
    assert_stderr --regexp "no configuration for Central API \(CAPI\) in '$(echo $CONFIG_YAML|sed s#//#/#g)'"
}

@test "cscli capi status" {
    ./instance-data load
    config_enable_capi
    rune -0 cscli capi register --schmilblick githubciXXXXXXXXXXXXXXXXXXXXXXXX
    rune -1 cscli capi status
    assert_stderr --partial "no scenarios installed, abort"

    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli capi status
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
    assert_line "You can successfully interact with Central API (CAPI)"
}

@test "capi register must be run from lapi" {
    config_disable_lapi
    rune -1 cscli capi register --schmilblick githubciXXXXXXXXXXXXXXXXXXXXXXXX
    assert_stderr --partial "local API is disabled -- this command must be run on the local API machine"
}
