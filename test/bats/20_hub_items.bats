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
    rune -1 cscli collections inspect crowdsecurity/sshd --no-metrics
    # XXX: it would be better to trigger this during parse, not sync
    assert_stderr "Error: failed to sync $HUB_DIR: while syncing collections sshd.yaml: 1.2.3.4: Invalid Semantic Version"
}

@test "removing or purging an item already removed by hand" {
    rune -0 cscli parsers install crowdsecurity/syslog-logs
    rune -0 cscli parsers inspect crowdsecurity/syslog-logs -o json
    rune -0 jq -r '.local_path' <(output)
    rune -0 rm "$(output)"

    rune -0 cscli parsers remove crowdsecurity/syslog-logs
    assert_output "Nothing to do."

    rune -0 cscli parsers inspect crowdsecurity/syslog-logs -o json
    rune -0 jq -r '.path' <(output)
    rune -0 rm "$HUB_DIR/$(output)"

    rune -0 cscli parsers remove crowdsecurity/syslog-logs --purge
    assert_output "Nothing to do."
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
    assert_stderr --partial "collection crowdsecurity/sshd is tainted by local changes"
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
    rune -0 cscli collections install foobar.yaml
    assert_output --partial "Nothing to do."
    rune -0 cscli collections install foobar.yaml --force
    assert_output --partial "Nothing to do."
    rune -0 cscli collections install --download-only foobar.yaml
    assert_output --partial "Nothing to do."
}

@test "a local item cannot be removed by cscli" {
    rune -0 mkdir -p "$CONFIG_DIR/scenarios"
    rune -0 touch "$CONFIG_DIR/scenarios/foobar.yaml"
    rune -0 cscli scenarios remove foobar.yaml
    assert_output - <<-EOT
	WARN scenarios:foobar.yaml is a local item, please delete manually
	Nothing to do.
	EOT
    rune -0 cscli scenarios remove foobar.yaml --purge
    assert_output - <<-EOT
	WARN scenarios:foobar.yaml is a local item, please delete manually
	Nothing to do.
	EOT
    rune -0 cscli scenarios remove foobar.yaml --force
    assert_output - <<-EOT
	WARN scenarios:foobar.yaml is a local item, please delete manually
	Nothing to do.
	EOT

    rune -0 cscli scenarios install crowdsecurity/ssh-bf

    rune -0 cscli scenarios remove --all
    assert_line "WARN scenarios:foobar.yaml is a local item, please delete manually"
    assert_line "disabling scenarios:crowdsecurity/ssh-bf"

    rune -0 cscli scenarios remove --all --purge
    assert_line "WARN scenarios:foobar.yaml is a local item, please delete manually"
    assert_line "purging scenarios:crowdsecurity/ssh-bf"
}

@test "a dangling link is reported with a warning" {
    rune -0 mkdir -p "$CONFIG_DIR/collections"
    rune -0 ln -s /this/does/not/exist.yaml "$CONFIG_DIR/collections/foobar.yaml"
    rune -0 cscli hub list
    assert_stderr --partial "Ignoring file $CONFIG_DIR/collections/foobar.yaml: lstat /this/does/not/exist.yaml: no such file or directory"
    rune -0 cscli hub list -o json
    rune -0 jq '.collections' <(output)
    assert_json '[]'
}

@test "replacing a symlink with a regular file makes a local item" {
    rune -0 cscli parsers install crowdsecurity/caddy-logs
    rune -0 rm "$CONFIG_DIR/parsers/s01-parse/caddy-logs.yaml"
    rune -0 cp "$HUB_DIR/parsers/s01-parse/crowdsecurity/caddy-logs.yaml" "$CONFIG_DIR/parsers/s01-parse/caddy-logs.yaml"
    rune -0 cscli hub list
    rune -0 cscli parsers inspect crowdsecurity/caddy-logs -o json
    rune -0 jq -e '[.tainted,.local,.local_version==false,true,"?"]' <(output)
    refute_stderr
}

@test "tainted hub file, not enabled, install --force should repair" {
    rune -0 cscli scenarios install crowdsecurity/ssh-bf
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    local_path="$(jq -r '.local_path' <(output))"
    echo >> "$local_path"
    rm "$local_path"
    rune -0 cscli scenarios install crowdsecurity/ssh-bf --force
    rune -0 cscli scenarios inspect crowdsecurity/ssh-bf -o json
    rune -0 jq -c '.tainted' <(output)
    assert_output 'false'
}

@test "don't traverse hidden directories (starting with a dot)" {
    rune -0 mkdir -p "$CONFIG_DIR/scenarios/.foo"
    rune -0 touch "$CONFIG_DIR/scenarios/.foo/bar.yaml"
    rune -0 cscli hub list --trace
    assert_stderr --partial "skipping hidden directory $CONFIG_DIR/scenarios/.foo"
}

@test "allow symlink to target inside a hidden directory" {
    # k8s config maps use hidden directories and links when mounted
    rune -0 mkdir -p "$CONFIG_DIR/scenarios/.foo"

    # ignored
    rune -0 touch "$CONFIG_DIR/scenarios/.foo/hidden.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output 0

    # real file
    rune -0 touch "$CONFIG_DIR/scenarios/myfoo.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output 1

    rune -0 rm "$CONFIG_DIR/scenarios/myfoo.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output 0

    # link to ignored is not ignored, and the name comes from the link
    rune -0 ln -s "$CONFIG_DIR/scenarios/.foo/hidden.yaml" "$CONFIG_DIR/scenarios/myfoo.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq -c '[.scenarios[].name] | sort' <(output)
    assert_json '["myfoo.yaml"]'
}

@test "item files can be links to links" {
    rune -0 mkdir -p "$CONFIG_DIR"/scenarios/{.foo,.bar}

    rune -0 ln -s "$CONFIG_DIR/scenarios/.foo/hidden.yaml" "$CONFIG_DIR/scenarios/.bar/hidden.yaml"

    # link to a danling link
    rune -0 ln -s "$CONFIG_DIR/scenarios/.bar/hidden.yaml" "$CONFIG_DIR/scenarios/myfoo.yaml"
    rune -0 cscli scenarios list
    assert_stderr --partial "Ignoring file $CONFIG_DIR/scenarios/myfoo.yaml: lstat $CONFIG_DIR/scenarios/.foo/hidden.yaml: no such file or directory"
    rune -0 cscli scenarios list -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output 0

    # detect link loops
    rune -0 ln -s "$CONFIG_DIR/scenarios/.bar/hidden.yaml" "$CONFIG_DIR/scenarios/.foo/hidden.yaml"
    rune -0 cscli scenarios list
    assert_stderr --partial "Ignoring file $CONFIG_DIR/scenarios/myfoo.yaml: too many levels of symbolic links"

    rune -0 rm "$CONFIG_DIR/scenarios/.foo/hidden.yaml"
    rune -0 touch "$CONFIG_DIR/scenarios/.foo/hidden.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq '.scenarios | length' <(output)
    assert_output 1
}

@test "item files can be in a subdirectory" {
    rune -0 mkdir -p "$CONFIG_DIR/scenarios/sub/sub2/sub3"
    rune -0 touch "$CONFIG_DIR/scenarios/sub/imlocal.yaml"
    # subdir name is now part of the item name
    rune -0 cscli scenarios inspect sub/imlocal.yaml -o json
    rune -0 jq -e '[.tainted,.local==false,true]' <(output)
    rune -0 rm "$CONFIG_DIR/scenarios/sub/imlocal.yaml"

    rune -0 ln -s "$HUB_DIR/scenarios/crowdsecurity/smb-bf.yaml" "$CONFIG_DIR/scenarios/sub/smb-bf.yaml"
    rune -0 cscli scenarios inspect crowdsecurity/smb-bf -o json
    rune -0 jq -e '[.tainted,.local==false,false]' <(output)
    rune -0 rm "$CONFIG_DIR/scenarios/sub/smb-bf.yaml"

    rune -0 ln -s "$HUB_DIR/scenarios/crowdsecurity/smb-bf.yaml" "$CONFIG_DIR/scenarios/sub/sub2/sub3/smb-bf.yaml"
    rune -0 cscli scenarios inspect crowdsecurity/smb-bf -o json
    rune -0 jq -e '[.tainted,.local==false,false]' <(output)
}

@test "same file name for local items in different subdirectories" {
    rune -0 mkdir -p "$CONFIG_DIR"/scenarios/{foo,bar}
    rune -0 touch "$CONFIG_DIR/scenarios/foo/local.yaml"
    rune -0 touch "$CONFIG_DIR/scenarios/bar/local.yaml"
    rune -0 cscli scenarios list -o json
    rune -0 jq -c '[.scenarios[].name] | sort' <(output)
    assert_json '["bar/local.yaml","foo/local.yaml"]'
}
