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
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "${FILE} config.yaml.local - cscli (log_level)" {
    yq e '.common.log_level="warning"' -i "${CONFIG_YAML}"
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "warning"

    echo "{'common':{'log_level':'debug'}}" >"${CONFIG_YAML}.local"
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "debug"
}

@test "${FILE} config.yaml.local - cscli (log_level - with envvar)" {
    yq e '.common.log_level="warning"' -i "${CONFIG_YAML}"
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "warning"

    export CROWDSEC_LOG_LEVEL=debug
    echo "{'common':{'log_level':'${CROWDSEC_LOG_LEVEL}'}}" >"${CONFIG_YAML}.local"
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "debug"
}

@test "${FILE} config.yaml.local - crowdsec (listen_url)" {
    run -0 ./instance-crowdsec start
    run -0 ./lib/util/wait-for-port -q 8080
    run -0 ./instance-crowdsec stop

    echo "{'api':{'server':{'listen_uri':127.0.0.1:8083}}}" >"${CONFIG_YAML}.local"
    run -0 ./instance-crowdsec start
    run -0 ./lib/util/wait-for-port -q 8083
    run -1 ./lib/util/wait-for-port -q 8080
    run -0 ./instance-crowdsec stop

    rm -f "${CONFIG_YAML}.local"
    run -0 ./instance-crowdsec start
    run -1 ./lib/util/wait-for-port -q 8083
    run -0 ./lib/util/wait-for-port -q 8080
}

@test "${FILE} local_api_credentials.yaml.local" {
    echo "{'api':{'server':{'listen_uri':127.0.0.1:8083}}}" >"${CONFIG_YAML}.local"
    run -0 ./instance-crowdsec start
    run -0 ./lib/util/wait-for-port -q 8083

    run -0 yq e '.api.client.credentials_path' <"${CONFIG_YAML}"
    LOCAL_API_CREDENTIALS="${output}"

    run -1 cscli decisions list
    echo "{'url':'http://127.0.0.1:8083'}" >"${LOCAL_API_CREDENTIALS}.local"
    run -0 cscli decisions list
}

@test "${FILE} simulation.yaml.local" {
    run -0 yq e '.config_paths.simulation_path' <"${CONFIG_YAML}"
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

@test "${FILE} profiles.yaml.local" {
    run -0 yq e '.api.server.profiles_path' <"${CONFIG_YAML}"
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
    ACQUIS_YAML=$(config_yq '.crowdsec_service.acquisition_path')
    echo -e "---\nfilename: ${tmpfile}\nlabels:\n  type: syslog\n" >>"${ACQUIS_YAML}"

    ./instance-crowdsec start
    sleep 1
    fake_log >>"${tmpfile}"
    sleep 1
    rm -f -- "${tmpfile}"
    run -0 cscli decisions list -o json
    run -0 jq -c '.[].decisions[0] | [.value,.type]' <(output)
    assert_output '["1.1.1.172","captcha"]'
}
