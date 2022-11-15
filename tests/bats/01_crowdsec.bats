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
    run -0 --separate-stderr timeout 2s "${CROWDSEC}" -h
    assert_stderr_line --regexp "Usage of .*:"

    run -0 --separate-stderr timeout 2s "${CROWDSEC}" --help
    assert_stderr_line --regexp "Usage of .*:"
}

@test "crowdsec (unknown flag)" {
    run -2 --separate-stderr timeout 2s "${CROWDSEC}" --foobar
    assert_stderr_line "flag provided but not defined: -foobar"
    assert_stderr_line --regexp "Usage of .*"
}

@test "crowdsec (unknown argument)" {
    run -2 --separate-stderr timeout 2s "${CROWDSEC}" trololo
    assert_stderr_line "argument provided but not defined: trololo"
    assert_stderr_line --regexp "Usage of .*"
}

@test "crowdsec (no api and no agent)" {
    run -1 --separate-stderr timeout 2s "${CROWDSEC}" -no-api -no-cs
    assert_stderr_line --partial "You must run at least the API Server or crowdsec"
}

@test "crowdsec - print error on exit" {
    # errors that cause program termination are printed to stderr, not only logs
    config_set '.db_config.type="meh"'
    run -1 --separate-stderr "${CROWDSEC}"
    refute_output
    assert_stderr --partial "unable to create database client: unknown database type 'meh'"
}

@test "CS_LAPI_SECRET not strong enough" {
    CS_LAPI_SECRET=foo run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    assert_stderr --partial "api server init: unable to run local API: controller init: CS_LAPI_SECRET not strong enough"
}

@test "crowdsec - reload (change of logfile, disabled agent)" {
    logdir1=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_old="${logdir1}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir1}\""

    run -0 ./instance-crowdsec start
    # PID="$output"
    assert_file_exist "$log_old"
    assert_file_contains "$log_old" "Starting processing data"

    logdir2=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_new="${logdir2}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir2}\""

    config_disable_agent

    sleep 5

    # this won't work as crowdsec-wrapper does not relay the signal
    # run -0 kill -HUP "$PID"

    # During functional tests, crowdsec is often run from a wrapper script,
    # which captures its output (for coverage reports) and cannot relay signals
    # at the same time. So instead of sending a SIGHUP to the wrapper, we send
    # it to the crowdsec process by name - with or without coverage.
    run pkill --ns $$ -HUP -f "$BIN_DIR/crowdsec.cover"
    run pkill --ns $$ -HUP -f "$BIN_DIR/crowdsec"

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

    run -0 ./instance-crowdsec stop
}

@test "crowdsec (error if the acquisition_path file is defined but missing)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"

    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    assert_stderr_line --partial "acquis.yaml: no such file or directory"
}

@test "crowdsec (error if acquisition_path is not defined and acquisition_dir is empty)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"

    config_set '.common.log_media="stdout"'
    run -124 --separate-stderr timeout 2s "${CROWDSEC}"
    # check warning
    assert_stderr_line --partial "no acquisition file found"
}

@test "crowdsec (error if acquisition_path and acquisition_dir are not defined)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"
    config_set '.crowdsec_service.acquisition_dir=""'

    config_set '.common.log_media="stdout"'
    run -124 --separate-stderr timeout 2s "${CROWDSEC}"
    # check warning
    assert_stderr_line --partial "no acquisition_path or acquisition_dir specified"
}

@test "crowdsec (no error if acquisition_path is empty string but acquisition_dir is not empty)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    mkdir -p "$ACQUIS_DIR"
    touch "$ACQUIS_DIR"/foo.yaml

    run -124 --separate-stderr timeout 2s "${CROWDSEC}"
}
