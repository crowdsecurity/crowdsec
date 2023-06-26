#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
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

@test "crowdsec (usage)" {
    rune -0 timeout 2s "${CROWDSEC}" -h
    assert_stderr_line --regexp "Usage of .*:"

    rune -0 timeout 2s "${CROWDSEC}" --help
    assert_stderr_line --regexp "Usage of .*:"
}

@test "crowdsec (unknown flag)" {
    rune -2 timeout 2s "${CROWDSEC}" --foobar
    assert_stderr_line "flag provided but not defined: -foobar"
    assert_stderr_line --regexp "Usage of .*"
}

@test "crowdsec (unknown argument)" {
    rune -2 timeout 2s "${CROWDSEC}" trololo
    assert_stderr_line "argument provided but not defined: trololo"
    assert_stderr_line --regexp "Usage of .*"
}

@test "crowdsec (no api and no agent)" {
    rune -1 timeout 2s "${CROWDSEC}" -no-api -no-cs
    assert_stderr_line --partial "You must run at least the API Server or crowdsec"
}

@test "crowdsec - print error on exit" {
    # errors that cause program termination are printed to stderr, not only logs
    config_set '.db_config.type="meh"'
    rune -1 "${CROWDSEC}"
    assert_stderr --partial "unable to create database client: unknown database type 'meh'"
}

@test "crowdsec - bad configuration (empty/missing common section)" {
    config_set '.common={}'
    rune -1 "${CROWDSEC}"
    refute_output
    assert_stderr --partial "unable to load configuration: common section is empty"

    config_set 'del(.common)'
    rune -1 "${CROWDSEC}"
    refute_output
    assert_stderr --partial "unable to load configuration: common section is empty"
}

@test "CS_LAPI_SECRET not strong enough" {
    CS_LAPI_SECRET=foo rune -1 timeout 2s "${CROWDSEC}"
    assert_stderr --partial "api server init: unable to run local API: controller init: CS_LAPI_SECRET not strong enough"
}

@test "crowdsec - reload (change of logfile, disabled agent)" {
    logdir1=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_old="${logdir1}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir1}\""

    rune -0 ./instance-crowdsec start-pid
    PID="$output"
    assert_file_exist "$log_old"
    assert_file_contains "$log_old" "Starting processing data"

    logdir2=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_new="${logdir2}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir2}\""

    config_disable_agent

    sleep 5

    rune -0 kill -HUP "$PID"

    for ((i=0; i<10; i++)); do
        sleep 1
        grep -q "serve: shutting down api server" <"$log_old" && break
    done

    echo "waited $i seconds"

    echo
    echo "OLD LOG"
    echo
    ls -la "$log_old" || true
    cat "$log_old" || true

    assert_file_contains "$log_old" "SIGHUP received, reloading"
    assert_file_contains "$log_old" "Crowdsec engine shutting down"
    assert_file_contains "$log_old" "Killing parser routines"
    assert_file_contains "$log_old" "Bucket routine exiting"
    assert_file_contains "$log_old" "serve: shutting down api server"

    sleep 5

    assert_file_exist "$log_new"

    for ((i=0; i<10; i++)); do
        sleep 1
        grep -q "Reload is finished" <"$log_old" && break
    done

    echo "waited $i seconds"

    echo
    echo "NEW LOG"
    echo
    ls -la "$log_new" || true
    cat "$log_new" || true

    assert_file_contains "$log_new" "CrowdSec Local API listening on 127.0.0.1:8080"
    assert_file_contains "$log_new" "Reload is finished"

    rune -0 ./instance-crowdsec stop
}

@test "crowdsec (error if the acquisition_path file is defined but missing)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"

    rune -1 timeout 2s "${CROWDSEC}"
    assert_stderr_line --partial "acquis.yaml: no such file or directory"
}

@test "crowdsec (error if acquisition_path is not defined and acquisition_dir is empty)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"

    config_set '.common.log_media="stdout"'
    rune -1 timeout 2s "${CROWDSEC}"
    # check warning
    assert_stderr --partial "no acquisition file found"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no data source enabled"
}

@test "crowdsec (error if acquisition_path and acquisition_dir are not defined)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"
    config_set '.crowdsec_service.acquisition_dir=""'

    config_set '.common.log_media="stdout"'
    rune -1 timeout 2s "${CROWDSEC}"
    # check warning
    assert_stderr --partial "no acquisition_path or acquisition_dir specified"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no data source enabled"
}

@test "crowdsec (no error if acquisition_path is empty string but acquisition_dir is not empty)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    mkdir -p "$ACQUIS_DIR"
    mv "$ACQUIS_YAML" "$ACQUIS_DIR"/foo.yaml

    rune -124 timeout 2s "${CROWDSEC}"

    # now, if foo.yaml is empty instead, there won't be valid datasources.

    cat /dev/null >"$ACQUIS_DIR"/foo.yaml

    rune -1 timeout 2s "${CROWDSEC}"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no data source enabled"
}

@test "crowdsec (disabled datasources)" {
    config_set '.common.log_media="stdout"'

    # a datasource cannot run - missing journalctl command

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    mkdir -p "$ACQUIS_DIR"
    cat >"$ACQUIS_DIR"/foo.yaml <<-EOT
	source: journalctl
	journalctl_filter:
	 - "_SYSTEMD_UNIT=ssh.service"
	labels:
	  type: syslog
	EOT

    rune -124 timeout 2s env PATH='' "${CROWDSEC}"
    #shellcheck disable=SC2016
    assert_stderr --partial 'datasource journalctl cannot be run: exec: "journalctl": executable file not found in $PATH'

    # if all datasources are disabled, crowdsec should exit

    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    rune -1 timeout 2s env PATH='' "${CROWDSEC}"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no data source enabled"
}

