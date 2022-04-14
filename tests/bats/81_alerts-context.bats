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

@test "$FILE 1.1.1.172 has context" {
    skip
    tmpfile=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp)
    touch "${tmpfile}"
    ACQUIS_YAML=$(config_yq '.crowdsec_service.acquisition_path')
    echo -e "---\nfilename: $tmpfile\nlabels:\n  type: syslog\n" >>"${ACQUIS_YAML}"

    CONTEXT_YAML=$(config_yq '.crowdsec_service.console_labels_path')
    echo -e "---\ntarget_user:\n- evt.Parsed.sshd_invalid_user\nsource_ip:\n- evt.Parsed.sshd_client_ip" >>"${CONTEXT_YAML}"

    ./instance-crowdsec start
    sleep 2
    fake_log >>"${tmpfile}"
    sleep 2
    rm -f -- "${tmpfile}"
    run cscli alerts list
    echo $output >&3
}
