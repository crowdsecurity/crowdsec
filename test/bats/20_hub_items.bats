#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
    INDEX_PATH=$(config_get '.config_paths.index_path')
    export INDEX_PATH
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    export CONFIG_DIR
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
    hub_strip_index
}

teardown() {
    ./instance-crowdsec stop
}

#----------
#
# Tests that don't need to be repeated for each hub type
#

@test "hub versions are correctly sorted during sync" {
    # hash of an empty file
    sha256_empty="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # add two versions with the same hash, that don't sort the same way
    # in a lexical vs semver sort. CrowdSec should report the latest version

    new_hub=$( \
        jq --arg DIGEST "$sha256_empty" <"$INDEX_PATH" \
        '. * {collections:{"crowdsecurity/sshd":{"versions":{"1.2":{"digest":$DIGEST, "deprecated": false}, "1.10": {"digest":$DIGEST, "deprecated": false}}}}}' \
    )
    echo "$new_hub" >"$INDEX_PATH"
 
    rune -0 cscli collections install crowdsecurity/sshd

    truncate -s 0 "$CONFIG_DIR/collections/sshd.yaml"

    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    # XXX: is this supposed to be tainted or up to date?
    rune -0 jq -c '[.local_version,.up_to_date,.tainted]' <(output)
    assert_json '["1.10",false,false]'
}

@test "do not unmarshal state attributes" {
    new_hub=$( \
        jq <"$INDEX_PATH" \
        '. * {parsers:{"crowdsecurity/syslog-logs":{"tainted":true, "installed":true, "local":true}}}'
    )
    echo "$new_hub" >"$INDEX_PATH"

    rune -0 cscli parsers inspect crowdsecurity/syslog-logs --no-metrics
    assert_output --partial 'tainted: false'
    assert_output --partial 'installed: false'
    assert_output --partial 'local: false'
}

@test "hub index with invalid (non semver) version numbers" {
    rune -0 cscli collections remove crowdsecurity/sshd --purge

    new_hub=$( \
        jq <"$INDEX_PATH" \
        '. * {collections:{"crowdsecurity/sshd":{"versions":{"1.2.3.4":{"digest":"foo", "deprecated": false}}}}}' \
    )
    echo "$new_hub" >"$INDEX_PATH"
 
    rune -0 cscli collections install crowdsecurity/sshd
    rune -1 cscli collections inspect crowdsecurity/sshd --no-metrics -o json
    # XXX: we are on the verbose side here...
    rune -0 jq -r ".msg" <(stderr)
    assert_output --regexp "failed to read Hub index: failed to sync items: failed to scan .*: while syncing collections sshd.yaml: 1.2.3.4: Invalid Semantic Version. Run 'sudo cscli hub update' to download the index again"
}

@test "removing or purging an item already removed by hand" {
    rune -0 cscli parsers install crowdsecurity/syslog-logs
    rune -0 cscli parsers inspect crowdsecurity/syslog-logs -o json
    rune -0 jq -r '.local_path' <(output)
    rune -0 rm "$(output)"

    rune -0 cscli parsers remove crowdsecurity/syslog-logs --debug
    assert_stderr --partial "removing crowdsecurity/syslog-logs: not installed -- no need to remove"

    rune -0 cscli parsers inspect crowdsecurity/syslog-logs -o json
    rune -0 jq -r '.path' <(output)
    rune -0 rm "$HUB_DIR/$(output)"

    rune -0 cscli parsers remove crowdsecurity/syslog-logs --purge --debug
    assert_stderr --partial "removing crowdsecurity/syslog-logs: not downloaded -- no need to remove"

    rune -0 cscli parsers remove crowdsecurity/linux --all --error --purge --force
    rune -0 cscli collections remove crowdsecurity/linux --all --error --purge --force
    refute_output
    refute_stderr
}

@test "a local item is not tainted" {
    # not from cscli... inspect
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 touch "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli collections inspect foobar.yaml -o json
    rune -0 jq -e '[.tainted,.local==false,true]' <(output)

    rune -0 cscli collections install crowdsecurity/sshd
    rune -0 truncate -s0 "$CONFIG_DIR/collections/sshd.yaml"
    rune -0 cscli collections inspect crowdsecurity/sshd -o json
    rune -0 jq -e '[.tainted,.local==true,false]' <(output)

    # and not from hub update
    rune -0 cscli hub update
    assert_stderr --partial "collection crowdsecurity/sshd is tainted"
    refute_stderr --partial "collection foobar.yaml is tainted"
}

@test "a local item's name defaults to its filename" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 touch "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli collections list -o json
    rune -0 jq -r '.[][].name' <(output)
    assert_output "foobar.yaml"
    rune -0 cscli collections list foobar.yaml
    rune -0 cscli collections inspect foobar.yaml -o json
    rune -0 jq -e '[.installed,.local==true,true]' <(output)
}

@test "a local item can provide its own name" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    echo "name: hi-its-me" > "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli collections list -o json
    rune -0 jq -r '.[][].name' <(output)
    assert_output "hi-its-me"
    rune -0 cscli collections list hi-its-me
    rune -0 cscli collections inspect hi-its-me -o json
    rune -0 jq -e '[.installed,.local]==[true,true]' <(output)
}

@test "a local item cannot be downloaded by cscli" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 touch "$CONFIG_DIR/collections/foobar.yaml"
    rune -1 cscli collections install foobar.yaml
    assert_stderr --partial "failed to download item: foobar.yaml is local, can't download"
    rune -1 cscli collections install foobar.yaml --force
    assert_stderr --partial "failed to download item: foobar.yaml is local, can't download"
}

@test "a local item cannot be removed by cscli" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 touch "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli collections remove foobar.yaml
    assert_stderr --partial "foobar.yaml is a local item, please delete manually"
    rune -0 cscli collections remove foobar.yaml --purge
    assert_stderr --partial "foobar.yaml is a local item, please delete manually"
    rune -0 cscli collections remove foobar.yaml --force
    assert_stderr --partial "foobar.yaml is a local item, please delete manually"
    rune -0 cscli collections remove --all
    assert_stderr --partial "foobar.yaml is a local item, please delete manually"
    rune -0 cscli collections remove --all --purge
    assert_stderr --partial "foobar.yaml is a local item, please delete manually"
}

@test "a dangling link is reported with a warning" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 ln -s /this/does/not/exist.yaml "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "link target does not exist: $CONFIG_DIR/collections/foobar.yaml -> /this/does/not/exist.yaml"
    rune -0 cscli hub list -o json
    rune -0 jq '.collections' <(output)
    assert_json '[]'
}
