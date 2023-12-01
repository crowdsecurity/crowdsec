#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    export CONFIG_DIR
    CONTEXT_YAML="$CONFIG_DIR/console/context.yaml"
    export CONTEXT_YAML
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    config_set '.common.log_media="stdout"'
    mkdir -p "$CONFIG_DIR/console"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "attempt to load from default context file, ignore if missing" {
    rune -0 rm -f "$CONTEXT_YAML"
    rune -0 "$CROWDSEC" -t --trace
    assert_stderr --partial "loading console context from $CONTEXT_YAML"
}

@test "error if context file is explicitly set but does not exist" {
    config_set ".crowdsec_service.console_context_path=\"$CONTEXT_YAML\""
    rune -0 rm -f "$CONTEXT_YAML"
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "while checking console_context_path: stat $CONTEXT_YAML: no such file or directory"
}

@test "context file is bad" {
    echo "bad yaml" > "$CONTEXT_YAML"
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "while loading context from $CONTEXT_YAML: yaml: unmarshal errors"
}

@test "context file is good" {
    echo '{"source_ip":["evt.Parsed.source_ip"]}' > "$CONTEXT_YAML"
    rune -0 "$CROWDSEC" -t --debug
    assert_stderr --partial 'console context to send: {"source_ip":["evt.Parsed.source_ip"]}'
}
