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

    cscli collections install crowdsecurity/sshd --error
    cscli parsers install crowdsecurity/syslog-logs --error
    cscli parsers install crowdsecurity/dateparse-enrich --error

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
    tmpfile=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp)
    touch "${tmpfile}"
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    echo -e "---\nfilename: ${tmpfile}\nlabels:\n  type: syslog\n" >>"${ACQUIS_YAML}"

    ./instance-crowdsec start
    fake_log >>"${tmpfile}"
    sleep 2
    rm -f -- "${tmpfile}"
    rune -0 cscli decisions list -o json
    rune -0 jq -r '.[].decisions[0].value' <(output)
    assert_output '1.1.1.172'
}
