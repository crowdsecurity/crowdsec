#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
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
    hub_purge_all
    hub_strip_index
}

teardown() {
    :
}

#----------

@test "cscli hub list" {
    # no items
    rune -0 cscli hub list
    assert_output --regexp ".*COLLECTIONS.*PARSERS.*SCENARIOS.*POSTOVERFLOWS.*"
    rune -0 cscli hub list -o json
    assert_json '{parsers:[],scenarios:[],collections:[],postoverflows:[]}'
    rune -0 cscli hub list -o raw
    refute_output

    # some items
    rune -0 cscli parsers install crowdsecurity/whitelists
    rune -0 cscli scenarios install crowdsecurity/telnet-bf
    rune -0 cscli hub list
    assert_output --regexp ".*COLLECTIONS.*PARSERS.*crowdsecurity/whitelists.*SCENARIOS.*crowdsecurity/telnet-bf.*POSTOVERFLOWS.*"
    rune -0 cscli hub list -o json
    rune -0 jq -e '(.parsers | length == 1) and (.scenarios | length == 1)' <(output)
    rune -0 cscli hub list -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    refute_output --partial 'crowdsecurity/linux'

    # all items
    rune -0 cscli hub list -a
    assert_output --regexp ".*COLLECTIONS.*crowdsecurity/linux.*PARSERS.*crowdsecurity/whitelists.*SCENARIOS.*crowdsecurity/telnet-bf.*POSTOVERFLOWS.*"
    rune -0 cscli hub list -a -o json
    rune -0 jq -e '(.parsers | length > 1) and (.scenarios | length > 1)' <(output)
    rune -0 cscli hub list -a -o raw
    assert_output --partial 'crowdsecurity/whitelists'
    assert_output --partial 'crowdsecurity/telnet-bf'
    assert_output --partial 'crowdsecurity/linux'
}

@test "cscli hub update" {
    #XXX: todo
    :
}

@test "cscli hub upgrade" {
    #XXX: todo
    :
}

@test "cscli hub upgrade --force" {
    #XXX: todo
    :
}
