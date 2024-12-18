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
    # don't run crowdsec here, not all tests require a running instance
}

teardown() {
    cd "$TEST_DIR" || exit 1
    ./instance-crowdsec stop
}

#----------

@test "cscli lapi status" {
    rune -0 ./instance-crowdsec start
    rune -0 cscli lapi status

    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli - missing LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    rm -f "$LOCAL_API_CREDENTIALS"
    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: while reading yaml file: open $LOCAL_API_CREDENTIALS: no such file or directory"

    rune -1 cscli alerts list
    assert_stderr --partial "loading api client: while reading yaml file: open $LOCAL_API_CREDENTIALS: no such file or directory"

    rune -1 cscli decisions list
    assert_stderr --partial "loading api client: while reading yaml file: open $LOCAL_API_CREDENTIALS: no such file or directory"
}

@test "cscli - empty LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    : > "$LOCAL_API_CREDENTIALS"
    rune -1 cscli lapi status
    assert_stderr --partial "no credentials or URL found in api client configuration '$LOCAL_API_CREDENTIALS'"

    rune -1 cscli alerts list
    assert_stderr --partial "no credentials or URL found in api client configuration '$LOCAL_API_CREDENTIALS'"

    rune -1 cscli decisions list
    assert_stderr --partial "no credentials or URL found in api client configuration '$LOCAL_API_CREDENTIALS'"
}

@test "cscli - LAPI credentials file can reference env variables" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    URL=$(config_get "$LOCAL_API_CREDENTIALS" '.url')
    export URL
    LOGIN=$(config_get "$LOCAL_API_CREDENTIALS" '.login')
    export LOGIN
    PASSWORD=$(config_get "$LOCAL_API_CREDENTIALS" '.password')
    export PASSWORD

    # shellcheck disable=SC2016
    echo '{"url":"$URL","login":"$LOGIN","password":"$PASSWORD"}' > "$LOCAL_API_CREDENTIALS".local

    config_set '.crowdsec_service.enable=false'
    rune -0 ./instance-crowdsec start

    rune -0 cscli lapi status
    assert_output --partial "You can successfully interact with Local API (LAPI)"

    rm "$LOCAL_API_CREDENTIALS".local

    # shellcheck disable=SC2016
    config_set "$LOCAL_API_CREDENTIALS" '.url="$URL"'
    # shellcheck disable=SC2016
    config_set "$LOCAL_API_CREDENTIALS" '.login="$LOGIN"'
    # shellcheck disable=SC2016
    config_set "$LOCAL_API_CREDENTIALS" '.password="$PASSWORD"'

    rune -0 cscli lapi status
    assert_output --partial "You can successfully interact with Local API (LAPI)"

    # but if a variable is not defined, there is no specific error message
    unset URL
    rune -1 cscli lapi status
    # shellcheck disable=SC2016
    assert_stderr --partial 'BaseURL must have a trailing slash'
}

@test "cscli - missing LAPI client settings" {
    config_set 'del(.api.client)'
    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: no API client section in configuration"

    rune -1 cscli alerts list
    assert_stderr --partial "loading api client: no API client section in configuration"

    rune -1 cscli decisions list
    assert_stderr --partial "loading api client: no API client section in configuration"
}

@test "cscli - malformed LAPI url" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "$LOCAL_API_CREDENTIALS" '.url="http://127.0.0.1:-80"'

    rune -1 cscli lapi status
    assert_stderr 'Error: failed to authenticate to Local API (LAPI): parse "http://127.0.0.1:-80/": invalid port ":-80" after host'
}

@test "cscli - bad LAPI password" {
    rune -0 ./instance-crowdsec start
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "$LOCAL_API_CREDENTIALS" '.password="meh"'

    rune -1 cscli lapi status
    assert_stderr 'Error: failed to authenticate to Local API (LAPI): API error: incorrect Username or Password'
}

@test "cscli lapi register / machines validate" {
    rune -1 cscli lapi register
    assert_stderr --partial "connection refused"

    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')

    rune -0 ./instance-crowdsec start
    rune -0 cscli lapi register
    assert_stderr --partial "Successfully registered to Local API"
    assert_stderr --partial "Local API credentials written to '$LOCAL_API_CREDENTIALS'"
    assert_stderr --partial "Run 'sudo systemctl reload crowdsec' for the new configuration to be effective."

    LOGIN=$(config_get "$LOCAL_API_CREDENTIALS" '.login')

    rune -0 cscli machines inspect "$LOGIN" -o json
    rune -0 jq -r '.isValidated' <(output)
    assert_output "null"

    rune -0 cscli machines validate "$LOGIN"

    rune -0 cscli machines inspect "$LOGIN" -o json
    rune -0 jq -r '.isValidated' <(output)
    assert_output "true"
}

@test "cscli lapi register --machine" {
    rune -0 ./instance-crowdsec start
    rune -0 cscli lapi register --machine newmachine
    rune -0 cscli machines validate newmachine
    rune -0 cscli machines inspect newmachine -o json
    rune -0 jq -r '.isValidated' <(output)
    assert_output "true"
}

@test "cscli lapi register --token (ignored)" {
    # A token is ignored if the server is not configured with it
    rune -1 cscli lapi register --machine newmachine --token meh
    assert_stderr --partial "connection refused"

    rune -0 ./instance-crowdsec start
    rune -1 cscli lapi register --machine newmachine --token meh
    assert_stderr --partial '422 Unprocessable Entity: API error: http code 422, invalid request:'
    assert_stderr --partial 'registration_token in body should be at least 32 chars long'

    rune -0 cscli lapi register --machine newmachine --token 12345678901234567890123456789012
    assert_stderr --partial "Successfully registered to Local API"

    rune -0 cscli machines inspect newmachine -o json
    rune -0 jq -r '.isValidated' <(output)
    assert_output "null"
}

@test "cscli lapi register --token" {
    config_set '.api.server.auto_registration.enabled=true'
    config_set '.api.server.auto_registration.token="12345678901234567890123456789012"'
    config_set '.api.server.auto_registration.allowed_ranges=["127.0.0.1/32"]'

    rune -0 ./instance-crowdsec start

    rune -1 cscli lapi register --machine malicious --token 123456789012345678901234badtoken
    assert_stderr --partial "401 Unauthorized: API error: invalid token for auto registration"
    rune -1 cscli machines inspect malicious
    # XXX: we may want to remove this warning
    assert_stderr --partial 'QueryMachineByID : ent: machine not found'
    assert_stderr --partial "Error: unable to read machine data 'malicious': user 'malicious': user doesn't exist"

    rune -0 cscli lapi register --machine newmachine --token 12345678901234567890123456789012
    assert_stderr --partial "Successfully registered to Local API"
    rune -0 cscli machines inspect newmachine -o json
    rune -0 jq -r '.isValidated' <(output)
    assert_output "true"
}

@test "cscli lapi register --token (bad source ip)" {
    config_set '.api.server.auto_registration.enabled=true'
    config_set '.api.server.auto_registration.token="12345678901234567890123456789012"'
    config_set '.api.server.auto_registration.allowed_ranges=["127.0.0.2/32"]'

    rune -0 ./instance-crowdsec start

    rune -1 cscli lapi register --machine outofrange --token 12345678901234567890123456789012
    assert_stderr --partial "401 Unauthorized: API error: IP not in allowed range for auto registration"
    rune -1 cscli machines inspect outofrange -o json
    assert_stderr --partial "unable to read machine data 'outofrange': user 'outofrange': user doesn't exist"
}
