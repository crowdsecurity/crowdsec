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

@test "detect available context" {
    rune -0 cscli lapi context detect -a
    rune -0 yq -o json <(output)
    assert_json '{"Acquisition":["evt.Line.Module","evt.Line.Raw","evt.Line.Src"]}'

    rune -0 cscli parsers install crowdsecurity/dateparse-enrich
    rune -0 cscli lapi context detect crowdsecurity/dateparse-enrich
    rune -0 yq -o json '.crowdsecurity/dateparse-enrich' <(output)
    assert_json '["evt.MarshaledTime","evt.Meta.timestamp"]'
}

@test "attempt to load from default context file, ignore if missing" {
    rune -0 rm -f "$CONTEXT_YAML"
    rune -0 "$CROWDSEC" -t --trace
    assert_stderr --partial "loading console context from $CONTEXT_YAML"
}

@test "error if context file is explicitly set but does not exist" {
    config_set ".crowdsec_service.console_context_path=strenv(CONTEXT_YAML)"
    rune -0 rm -f "$CONTEXT_YAML"
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "while checking console_context_path: stat $CONTEXT_YAML: no such file or directory"
}

@test "context file is bad" {
    echo "bad yaml" > "$CONTEXT_YAML"
    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "while loading context: $CONTEXT_YAML: yaml: unmarshal errors"
}

@test "context file is good" {
    echo '{"source_ip":["evt.Parsed.source_ip"]}' > "$CONTEXT_YAML"
    rune -0 "$CROWDSEC" -t --debug
    # the log content may have quotes escaped or not, depending on tty detection
    assert_stderr --regexp 'console context to send: .*source_ip.*evt.Parsed.source_ip'
}

@test "context file is from hub (local item)" {
    mkdir -p "$CONFIG_DIR/contexts"
    config_set "del(.crowdsec_service.console_context_path)"
    echo '{"context":{"source_ip":["evt.Parsed.source_ip"]}}' > "$CONFIG_DIR/contexts/foobar.yaml"
    rune -0 "$CROWDSEC" -t --trace
    assert_stderr --partial "loading console context from $CONFIG_DIR/contexts/foobar.yaml"
    assert_stderr --regexp 'console context to send: .*source_ip.*evt.Parsed.source_ip'
}

@test "merge multiple contexts" {
    mkdir -p "$CONFIG_DIR/contexts"
    echo '{"context":{"one":["evt.Parsed.source_ip"]}}' > "$CONFIG_DIR/contexts/one.yaml"
    echo '{"context":{"two":["evt.Parsed.source_ip"]}}' > "$CONFIG_DIR/contexts/two.yaml"
    rune -0 "$CROWDSEC" -t --trace
    assert_stderr --partial "loading console context from $CONFIG_DIR/contexts/one.yaml"
    assert_stderr --partial "loading console context from $CONFIG_DIR/contexts/two.yaml"
    assert_stderr --regexp 'console context to send: .*one.*evt.Parsed.source_ip.*two.*evt.Parsed.source_ip'
}

@test "merge contexts from hub and context.yaml file" {
    mkdir -p "$CONFIG_DIR/contexts"
    echo '{"context":{"one":["evt.Parsed.source_ip"]}}' > "$CONFIG_DIR/contexts/one.yaml"
    echo '{"one":["evt.Parsed.source_ip_2"]}' > "$CONFIG_DIR/console/context.yaml"
    rune -0 "$CROWDSEC" -t --trace
    assert_stderr --partial "loading console context from $CONFIG_DIR/contexts/one.yaml"
    assert_stderr --partial "loading console context from $CONFIG_DIR/console/context.yaml"
    assert_stderr --regexp 'console context to send: .*one.*evt.Parsed.source_ip.*evt.Parsed.source_ip_2'
}
