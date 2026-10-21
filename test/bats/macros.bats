#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    export CONFIG_DIR
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    mkdir -p "$CONFIG_DIR/macros" "$CONFIG_DIR/parsers/s02-enrich"
    cat <<-EOT >"$CONFIG_DIR/parsers/s02-enrich/macro-user.yaml"
	name: test/macro-user
	filter: IsSshd()
	statics:
	  - meta: uses_macro
	    value: "yes"
	EOT
}

#----------

@test "local macro item" {
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "unknown name IsSshd"

    echo "macros: {IsSshd: evt.Parsed.program == 'sshd'}" > "$CONFIG_DIR/macros/local.yaml"
    rune -0 cscli macros list -o json
    rune -0 jq -c '[.macros[] | [.name, .status]]' <(output)
    assert_json '[["local.yaml","enabled,local"]]'
    rune -0 "$CROWDSEC" -t
}

@test "macro names are unique across items" {
    echo "macros: {IsSshd: evt.Parsed.program == 'sshd'}" > "$CONFIG_DIR/macros/one.yaml"
    echo "macros: {IsSshd: evt.Parsed.program == 'sshd2'}" > "$CONFIG_DIR/macros/two.yaml"
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial 'while loading expression macros: macro "IsSshd" is defined by both one.yaml and two.yaml'
}
