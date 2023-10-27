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
    hub_uninstall_all
    hub_min=$(jq <"$HUB_DIR/.index.json" 'del(..|.content?) | del(..|.long_description?) | del(..|.deprecated?) | del (..|.labels?)')
    echo "$hub_min" >"$HUB_DIR/.index.json"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "cscli collections (dependencies)" {
    # inject a dependency: smb requires sshd
    hub_dep=$(jq <"$HUB_DIR/.index.json" '. * {collections:{"crowdsecurity/smb":{collections:["crowdsecurity/sshd"]}}}')
    echo "$hub_dep" >"$HUB_DIR/.index.json"

    # verify that installing smb brings sshd
    rune -0 cscli collections install crowdsecurity/smb
    rune -0 cscli collections list -o json
    rune -0 jq -e '[.collections[].name]==["crowdsecurity/smb","crowdsecurity/sshd"]' <(output)

    # verify that removing smb removes sshd too
    rune -0 cscli collections remove crowdsecurity/smb
    rune -0 cscli collections list -o json
    rune -0 jq -e '.collections | length == 0' <(output)

    # we can't remove sshd without --force
    rune -0 cscli collections install crowdsecurity/smb
    # XXX: should this be an error?
    rune -0 cscli collections remove crowdsecurity/sshd
    assert_stderr --partial "crowdsecurity/sshd belongs to collections: [crowdsecurity/smb]"
    assert_stderr --partial "Run 'sudo cscli collections remove crowdsecurity/sshd --force' if you want to force remove this collection"
    rune -0 cscli collections list -o json
    rune -0 jq -c '[.collections[].name]' <(output)
    assert_json '["crowdsecurity/smb","crowdsecurity/sshd"]'

    # use the --force
    rune -0 cscli collections remove crowdsecurity/sshd --force
    rune -0 cscli collections list -o json
    rune -0 jq -c '[.collections[].name]' <(output)
    assert_json '["crowdsecurity/smb"]'

    # and now smb is tainted!
    rune -0 cscli collections inspect crowdsecurity/smb -o json
    rune -0 jq -e '.tainted//false==true' <(output)
    rune -0 cscli collections remove crowdsecurity/smb --force

    # empty
    rune -0 cscli collections list -o json
    rune -0 jq -e '.collections | length == 0' <(output)

    # reinstall
    rune -0 cscli collections install crowdsecurity/smb --force

    # taint on sshd means smb is tainted as well
    rune -0 cscli collections inspect crowdsecurity/smb -o json
    jq -e '.tainted//false==false' <(output)
    echo "dirty" >"$CONFIG_DIR/collections/sshd.yaml"
    rune -0 cscli collections inspect crowdsecurity/smb -o json
    jq -e '.tainted//false==true' <(output)

    # now we can't remove smb without --force
    rune -1 cscli collections remove crowdsecurity/smb
    assert_stderr --partial "unable to disable crowdsecurity/smb: crowdsecurity/smb is tainted, use '--force' to overwrite"
}
