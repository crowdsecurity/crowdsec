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
    cscli collections install crowdsecurity/sshd --error
    cscli parsers install crowdsecurity/syslog-logs --error
    cscli parsers install crowdsecurity/dateparse-enrich --error
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "$FILE 1.1.1.172 has context" {
    tmpfile=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp)
    touch "${tmpfile}"

    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')

    cat <<-EOT >"${ACQUIS_YAML}"
	filename: $tmpfile
	labels:
	  type: syslog
	EOT

    # we set the path here because the default is empty
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    CONTEXT_YAML="$CONFIG_DIR/console/context.yaml"
    export CONTEXT_YAML
    config_set '.crowdsec_service.console_context_path=strenv(CONTEXT_YAML)'
    mkdir -p "$CONFIG_DIR/console"

    cat <<-EOT >"${CONTEXT_YAML}"
	target_user:
	- evt.Parsed.sshd_invalid_user
	source_ip:
	- evt.Parsed.sshd_client_ip
	source_host:
	- evt.Meta.machine
	EOT

    ./instance-crowdsec start
    sleep 2
    fake_log >>"${tmpfile}"
    sleep 2
    rm -f -- "${tmpfile}"

    rune -0 cscli alerts list -o json
    rune -0 jq '.[0].id' <(output)
    ALERT_ID="$output"
    rune -0 cscli alerts inspect "$ALERT_ID" -o json
    rune -0 jq -c '.meta | sort_by(.key) | map([.key,.value])' <(output)

    assert_json '[["source_host","[\"sd-126005\"]"],["source_ip","[\"1.1.1.172\"]"],["target_user","[\"netflix\"]"]]'
}
