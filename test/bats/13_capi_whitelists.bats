#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    CAPI_WHITELISTS_YAML="$CONFIG_DIR/capi-whitelists.yaml"
    export CAPI_WHITELISTS_YAML
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    config_set '.api.server.capi_whitelists_path=strenv(CAPI_WHITELISTS_YAML)'
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "capi_whitelists: file missing" {
    rune -1 timeout 1s "${CROWDSEC}"
    assert_stderr --partial "capi whitelist file '$CAPI_WHITELISTS_YAML' does not exist"
}

@test "capi_whitelists: empty file" {
    echo > "$CAPI_WHITELISTS_YAML"
    rune -1 timeout 1s "${CROWDSEC}"
    assert_stderr --partial "while parsing capi whitelist file '$CAPI_WHITELISTS_YAML': empty file"
}

@test "capi_whitelists: empty lists" {
    echo '{"ips": [], "cidrs": []}' > "$CAPI_WHITELISTS_YAML"
    rune -124 timeout 1s "${CROWDSEC}"
}

@test "capi_whitelists: bad ip" {
    echo '{"ips": ["blahblah"], "cidrs": []}' > "$CAPI_WHITELISTS_YAML"
    rune -1 timeout 1s "${CROWDSEC}"
    assert_stderr --partial "while parsing capi whitelist file '$CAPI_WHITELISTS_YAML': invalid IP address: blahblah"
}

@test "capi_whitelists: bad cidr" {
    echo '{"ips": [], "cidrs": ["blahblah"]}' > "$CAPI_WHITELISTS_YAML"
    rune -1 timeout 1s "${CROWDSEC}"
    assert_stderr --partial "while parsing capi whitelist file '$CAPI_WHITELISTS_YAML': invalid CIDR address: blahblah"
}

@test "capi_whitelists: file with ip and cidr values" {
    cat <<-EOT > "$CAPI_WHITELISTS_YAML"
	ips:
	- 1.2.3.4
	- 2.3.4.5
	cidrs:
	- 1.2.3.0/24
	EOT

    config_set '.common.log_level="trace"'
    rune -0 ./instance-crowdsec start
}
