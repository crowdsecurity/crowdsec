#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
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
    hub_uninstall_all
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli parsers list" {
    # no items
    rune -0 cscli parsers list
    assert_output --partial "PARSERS"
    rune -0 cscli parsers list -o json
    assert_json '{parsers:[]}'
    rune -0 cscli parsers list -o raw
    assert_output 'name,status,version,description'

    # some items
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    rune -0 cscli parsers list
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 grep -c enabled <(output)
    assert_output "2"

    rune -0 cscli parsers list -o json
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 jq '.parsers | length' <(output)
    assert_output "2"

    rune -0 cscli parsers list -o raw
    assert_output --partial crowdsecurity/whitelists
    assert_output --partial crowdsecurity/windows-auth
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli parsers list -a" {
    expected=$(jq <"$HUB_DIR/.index.json" -r '.parsers | length')

    rune -0 cscli parsers list -a
    rune -0 grep -c disabled <(output)
    assert_output "$expected"

    rune -0 cscli parsers list -o json -a
    rune -0 jq '.parsers | length' <(output)
    assert_output "$expected"

    rune -0 cscli parsers list -o raw -a
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "$expected"
}


@test "cscli parsers list [parser]..." {
    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    # list one item
    rune -0 cscli parsers list crowdsecurity/whitelists
    assert_output --partial "crowdsecurity/whitelists"
    refute_output --partial "crowdsecurity/windows-auth"

    # list multiple items
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth
    assert_output --partial "crowdsecurity/whitelists"
    assert_output --partial "crowdsecurity/windows-auth"

    rune -0 cscli parsers list crowdsecurity/whitelists -o json
    rune -0 jq '.parsers | length' <(output)
    assert_output "1"
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth -o json
    rune -0 jq '.parsers | length' <(output)
    assert_output "2"

    rune -0 cscli parsers list crowdsecurity/whitelists -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "1"
    rune -0 cscli parsers list crowdsecurity/whitelists crowdsecurity/windows-auth -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"
}

@test "cscli parsers list [parser]... (not installed / not existing)" {
    skip "not implemented yet"
    # not installed
    rune -1 cscli parsers list crowdsecurity/whitelists
    # not existing
    rune -1 cscli parsers list blahblah/blahblah
}

@test "cscli parsers install [parser]..." {
    rune -1 cscli parsers install
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'

    # simple install
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'installed: true'

    # not in hub
    rune -1 cscli parsers install crowdsecurity/blahblah
    assert_stderr --partial "can't find 'crowdsecurity/blahblah' in parsers"

    # autocorrect
    rune -1 cscli parsers install crowdsecurity/sshd-logz
    assert_stderr --partial "can't find 'crowdsecurity/sshd-logz' in parsers, did you mean crowdsecurity/sshd-logs?"

    # install multiple
    rune -0 cscli parsers install crowdsecurity/pgsql-logs crowdsecurity/postfix-logs
    rune -0 cscli parsers inspect crowdsecurity/pgsql-logs --no-metrics
    assert_output --partial 'crowdsecurity/pgsql-logs'
    assert_output --partial 'installed: true'
    rune -0 cscli parsers inspect crowdsecurity/postfix-logs --no-metrics
    assert_output --partial 'crowdsecurity/postfix-logs'
    assert_output --partial 'installed: true'
}

@test "cscli parsers install [parser]... (file location and download-only)" {
    # simple install
    rune -0 cscli parsers install crowdsecurity/whitelists --download-only
    rune -0 cscli parsers inspect crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'installed: false'
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
}

@test "cscli parsers inspect [parser]..." {
    rune -1 cscli parsers inspect
    assert_stderr --partial 'requires at least 1 arg(s), only received 0'
    ./instance-crowdsec start

    rune -1 cscli parsers inspect blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"

    # one item
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs --no-metrics
    assert_line 'type: parsers'
    assert_line 'stage: s01-parse'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # one item, with metrics
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs
    assert_line --partial 'Current metrics:'

    # one item, json
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o json
    rune -0 jq -c '[.type, .stage, .name, .author, .path, .installed]' <(output)
    # XXX: .installed is missing -- not false
    assert_json '["parsers","s01-parse","crowdsecurity/sshd-logs","crowdsecurity","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",null]'

    # one item, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs -o raw
    assert_line 'type: parsers'
    assert_line 'stage: s01-parse'
    assert_line 'name: crowdsecurity/sshd-logs'
    assert_line 'author: crowdsecurity'
    assert_line 'remote_path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml'
    assert_line 'installed: false'
    refute_line --partial 'Current metrics:'

    # multiple items
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists --no-metrics
    assert_output --partial 'crowdsecurity/sshd-logs'
    assert_output --partial 'crowdsecurity/whitelists'
    rune -1 grep -c 'Current metrics:' <(output)
    assert_output "0"

    # multiple items, with metrics
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists
    rune -0 grep -c 'Current metrics:' <(output)
    assert_output "2"

    # multiple items, json
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists -o json
    rune -0 jq -sc '[.[] | [.type, .stage, .name, .author, .path, .installed]]' <(output)
    assert_json '[["parsers","s01-parse","crowdsecurity/sshd-logs","crowdsecurity","parsers/s01-parse/crowdsecurity/sshd-logs.yaml",null],["parsers","s02-enrich","crowdsecurity/whitelists","crowdsecurity","parsers/s02-enrich/crowdsecurity/whitelists.yaml",null]]'

    # multiple items, raw
    rune -0 cscli parsers inspect crowdsecurity/sshd-logs crowdsecurity/whitelists -o raw
    assert_output --partial 'crowdsecurity/sshd-logs'
    assert_output --partial 'crowdsecurity/whitelists'
    run -1 grep -c 'Current metrics:' <(output)
    assert_output "0"
}

@test "cscli parsers remove [parser]..." {
    rune -1 cscli parsers remove
    assert_stderr --partial "specify at least one parser to remove or '--all'"

    rune -1 cscli parsers remove blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"

    # XXX: we can however remove a real item if it's not installed, or already removed
    rune -0 cscli parsers remove crowdsecurity/whitelists

    # XXX: have the --force ignore uninstalled items
    # XXX: maybe also with --purge

    # install, then remove, check files
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers remove crowdsecurity/whitelists
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    # delete is an alias for remove
    rune -0 cscli parsers install crowdsecurity/whitelists
    assert_file_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers delete crowdsecurity/whitelists
    assert_file_not_exists "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"

    # purge
    assert_file_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"
    rune -0 cscli parsers remove crowdsecurity/whitelists --purge
    assert_file_not_exists "$HUB_DIR/parsers/s02-enrich/crowdsecurity/whitelists.yaml"

    rune -0 cscli parsers install crowdsecurity/whitelists crowdsecurity/windows-auth

    # --all
    rune -0 cscli parsers list -o raw
    rune -0 grep -vc 'name,status,version,description' <(output)
    assert_output "2"

    rune -0 cscli parsers remove --all

    rune -0 cscli parsers list -o raw
    rune -1 grep -vc 'name,status,version,description' <(output)
    assert_output "0"
}

@test "cscli parsers upgrade [parser]..." {
    rune -1 cscli parsers upgrade
    assert_stderr --partial "specify at least one parser to upgrade or '--all'"

    # XXX: should this return 1 instead of log.Error?
    rune -0 cscli parsers upgrade blahblah/blahblah
    assert_stderr --partial "can't find 'blahblah/blahblah' in parsers"

    # XXX: same message if the item exists but is not installed, this is confusing
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_stderr --partial "can't find 'crowdsecurity/whitelists' in parsers"

    # hash of an empty file
    sha256_empty="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # add version 0.0 to the hub
    new_hub=$(jq --arg DIGEST "$sha256_empty" <"$HUB_DIR/.index.json" '. * {parsers:{"crowdsecurity/whitelists":{"versions":{"0.0":{"digest":$DIGEST, "deprecated": false}}}}}')
    echo "$new_hub" >"$HUB_DIR/.index.json"
 
    rune -0 cscli parsers install crowdsecurity/whitelists

    # bring the file to v0.0
    truncate -s 0 "$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="0.0"' <(output)

    # upgrade
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # taint
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    # XXX: should return error
    rune -0 cscli parsers upgrade crowdsecurity/whitelists
    assert_stderr --partial "crowdsecurity/whitelists is tainted, --force to overwrite"
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version=="?"' <(output)

    # force upgrade with taint
    rune -0 cscli parsers upgrade crowdsecurity/whitelists --force
    rune -0 cscli parsers inspect crowdsecurity/whitelists -o json
    rune -0 jq -e '.local_version==.version' <(output)

    # multiple items
    rune -0 cscli parsers install crowdsecurity/windows-auth
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    echo "dirty" >"$CONFIG_DIR/parsers/s01-parse/windows-auth.yaml"
    rune -0 cscli parsers list -o json
    rune -0 jq -e '[.parsers[].local_version]==["?","?"]' <(output)
    rune -0 cscli parsers upgrade crowdsecurity/whitelists crowdsecurity/windows-auth
    rune -0 jq -e '[.parsers[].local_version]==[.parsers[].version]' <(output)

    # upgrade all
    echo "dirty" >"$CONFIG_DIR/parsers/s02-enrich/whitelists.yaml"
    echo "dirty" >"$CONFIG_DIR/parsers/s01-parse/windows-auth.yaml"
    rune -0 cscli parsers upgrade --all
    rune -0 jq -e '[.parsers[].local_version]==[.parsers[].version]' <(output)
}



#@test "must use --force to remove a collection that belongs to another, which becomes tainted" {
#    # we expect no error since we may have multiple collections, some removed and some not
#    rune -0 cscli collections remove crowdsecurity/sshd
#    assert_stderr --partial "crowdsecurity/sshd belongs to other collections"
#    assert_stderr --partial "[crowdsecurity/linux]"
#
#    rune -0 cscli collections remove crowdsecurity/sshd --force
#    assert_stderr --partial "Removed symlink [crowdsecurity/sshd]"
#    rune -0 cscli collections inspect crowdsecurity/linux -o json
#    rune -0 jq -r '.tainted' <(output)
#    assert_output "true"
#}
#
#@test "can remove a collection" {
#    rune -0 cscli collections remove crowdsecurity/linux
#    assert_stderr --partial "Removed"
#    assert_stderr --regexp   ".*for the new configuration to be effective."
#    rune -0 cscli collections inspect crowdsecurity/linux -o human --no-metrics
#    assert_line 'installed: false'
#}
#
#@test "collections delete is an alias for collections remove" {
#    rune -0 cscli collections delete crowdsecurity/linux
#    assert_stderr --partial "Removed"
#    assert_stderr --regexp   ".*for the new configuration to be effective."
#}
#
#@test "removing a collection that does not exist is noop" {
#    rune -0 cscli collections remove crowdsecurity/apache2
#    refute_stderr --partial "Removed"
#    assert_stderr --regexp   ".*for the new configuration to be effective."
#}
#
#@test "can remove a removed collection" {
#    rune -0 cscli collections install crowdsecurity/mysql
#    rune -0 cscli collections remove crowdsecurity/mysql
#    assert_stderr --partial "Removed"
#    rune -0 cscli collections remove crowdsecurity/mysql
#    refute_stderr --partial "Removed"
#}
#
#@test "can remove all collections" {
#    # we may have this too, from package installs
#    rune cscli parsers delete crowdsecurity/whitelists
#    rune -0 cscli collections remove --all
#    assert_stderr --partial "Removed symlink [crowdsecurity/sshd]"
#    assert_stderr --partial "Removed symlink [crowdsecurity/linux]"
#    rune -0 cscli hub list -o json
#    assert_json '{collections:[],parsers:[],postoverflows:[],scenarios:[]}'
#    rune -0 cscli collections remove --all
#    assert_stderr --partial 'Disabled 0 items'
#}
#
#@test "a taint bubbles up to the top collection" {
#    coll=crowdsecurity/nginx
#    subcoll=crowdsecurity/base-http-scenarios
#    scenario=crowdsecurity/http-crawl-non_statics
#
#    # install a collection with dependencies
#    rune -0 cscli collections install "$coll"
#
#    # the collection, subcollection and scenario are installed and not tainted
#    # we have to default to false because tainted is (as of 1.4.6) returned
#    # only when true
#    rune -0 cscli collections inspect "$coll" -o json
#    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)
#    rune -0 cscli collections inspect "$subcoll" -o json
#    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)
#    rune -0 cscli scenarios inspect "$scenario" -o json
#    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)
#
#    # we taint the scenario
#    HUB_DIR=$(config_get '.config_paths.hub_dir')
#    yq e '.description="I am tainted"' -i "$HUB_DIR/scenarios/$scenario.yaml"
#
#    # the collection, subcollection and scenario are now tainted
#    rune -0 cscli scenarios inspect "$scenario" -o json
#    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
#    rune -0 cscli collections inspect "$subcoll" -o json
#    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
#    rune -0 cscli collections inspect "$coll" -o json
#    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
#}
#
## TODO test download-only
