#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

fake_log() {
    for _ in $(seq 1 6); do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424'
    done
}

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    run -0 config_get '.api.client.credentials_path'
    LOCAL_API_CREDENTIALS="${output}"
    export LOCAL_API_CREDENTIALS
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "config.yaml.local - cscli (log_level)" {
    config_set '.common.log_level="warning"'
    run -0 --separate-stderr cscli config show --key Config.Common.LogLevel
    assert_output "warning"

    echo "{'common':{'log_level':'debug'}}" >"${CONFIG_YAML}.local"
    run -0 --separate-stderr cscli config show --key Config.Common.LogLevel
    assert_output "debug"
}

@test "config.yaml.local - cscli (log_level - with envvar)" {
    config_set '.common.log_level="warning"'
    run -0 --separate-stderr cscli config show --key Config.Common.LogLevel
    assert_output "warning"

    export CROWDSEC_LOG_LEVEL=debug
    echo "{'common':{'log_level':'${CROWDSEC_LOG_LEVEL}'}}" >"${CONFIG_YAML}.local"
    run -0 --separate-stderr cscli config show --key Config.Common.LogLevel
    assert_output "debug"
}

@test "config.yaml.local - crowdsec (listen_url)" {
    # disable the agent or we'll need to patch api client credentials too
    run -0 config_disable_agent
    ./instance-crowdsec start
    run -0 ./bin/wait-for-port -q 8080
    ./instance-crowdsec stop
    run -1 ./bin/wait-for-port -q 8080

    echo "{'api':{'server':{'listen_uri':127.0.0.1:8083}}}" >"${CONFIG_YAML}.local"

    ./instance-crowdsec start
    run -0 ./bin/wait-for-port -q 8083
    run -1 ./bin/wait-for-port -q 8080
    ./instance-crowdsec stop

    rm -f "${CONFIG_YAML}.local"
    ./instance-crowdsec start
    run -1 ./bin/wait-for-port -q 8083
    run -0 ./bin/wait-for-port -q 8080
}

@test "local_api_credentials.yaml.local" {
    run -0 config_disable_agent
    echo "{'api':{'server':{'listen_uri':127.0.0.1:8083}}}" >"${CONFIG_YAML}.local"
    ./instance-crowdsec start
    run -0 ./bin/wait-for-port -q 8083

    run -1 cscli decisions list
    echo "{'url':'http://127.0.0.1:8083'}" >"${LOCAL_API_CREDENTIALS}.local"

    run -0 cscli decisions list
}

@test "simulation.yaml.local" {
    run -0 config_get '.config_paths.simulation_path'
    refute_output null
    SIMULATION="${output}"

    echo "simulation: off" >"${SIMULATION}"
    run -0 cscli simulation status -o human
    assert_output --partial "global simulation: disabled"

    echo "simulation: on" >"${SIMULATION}"
    run -0 cscli simulation status -o human
    assert_output --partial "global simulation: enabled"

    echo "simulation: off" >"${SIMULATION}.local"
    run -0 cscli simulation status -o human
    assert_output --partial "global simulation: disabled"

    rm -f "${SIMULATION}.local"
    run -0 cscli simulation status -o human
    assert_output --partial "global simulation: enabled"
}

@test "profiles.yaml.local" {
    run -0 --separate-stderr config_get '.api.server.profiles_path'
    refute_output null
    PROFILES="${output}"

    cat <<-EOT >"${PROFILES}.local"
	name: default_ip_remediation
	filters:
	 - Alert.Remediation == true && Alert.GetScope() == "Ip"
	decisions:
	 - type: captcha
	   duration: 2h
	on_success: break
	EOT

    tmpfile=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp)
    touch "${tmpfile}"
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    echo -e "---\nfilename: ${tmpfile}\nlabels:\n  type: syslog\n" >>"${ACQUIS_YAML}"

    ./instance-crowdsec start
    sleep .5
    fake_log >>"${tmpfile}"

    # this could be simplified, but some systems are slow and we don't want to
    # wait more than required
    for ((i=0;i<30;i++)); do
        sleep .5
        run -0 --separate-stderr cscli decisions list -o json
        run -0 jq --exit-status '.[].decisions[0] | [.value,.type] == ["1.1.1.172","captcha"]' <(output) && break
    done
    rm -f -- "${tmpfile}"
    [[ "${status}" -eq 0 ]] || fail "captcha not triggered"
}
