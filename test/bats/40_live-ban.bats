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
    # we reset config and data, but run the daemon only in the tests that need it
    ./instance-data load

    cscli collections install crowdsecurity/sshd --error >/dev/null
    cscli parsers install crowdsecurity/syslog-logs --error >/dev/null
    cscli parsers install crowdsecurity/dateparse-enrich --error >/dev/null
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "1.1.1.172 has been banned" {
    tmpfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    touch "$tmpfile"
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    echo -e "---\nfilename: ${tmpfile}\nlabels:\n  type: syslog\n" >>"$ACQUIS_YAML"

    ./instance-crowdsec start

    sleep 0.2

    fake_log >>"$tmpfile"

    sleep 0.2

    rm -f -- "$tmpfile"

    found=0
    # this may take some time in CI
    for _ in $(seq 1 10); do
        if cscli decisions list -o json | jq -r '.[].decisions[0].value' | grep -q '1.1.1.172'; then
            found=1
            break
        fi
        sleep 0.2
    done
    assert_equal 1 "$found"
}
