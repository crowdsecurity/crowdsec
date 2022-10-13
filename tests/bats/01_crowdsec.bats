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
    run -1 --separate-stderr "${BIN_DIR}/crowdsec"
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
    PID="$output"
    assert_file_exist "$log_old"
    assert_file_contains "$log_old" "Starting processing data"
    truncate -s0 "$log_old"

    logdir2=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_new="${logdir2}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir2}\""

    config_disable_agent

    run -0 kill -1 "$PID"

    for ((i=0; i<20; i++)); do
        sleep 1
        grep -q "killing all plugins" <"$log_old" && break
    done

    assert_file_contains "$log_old" "SIGHUP received, reloading"
    assert_file_contains "$log_old" "Crowdsec engine shutting down"
    assert_file_contains "$log_old" "Killing parser routines"
    assert_file_contains "$log_old" "Bucket routine exiting"
    assert_file_contains "$log_old" "serve: shutting down api server"
    assert_file_contains "$log_old" "plugingTomb dying"
    assert_file_contains "$log_old" "killing all plugins"

    assert_file_exist "$log_new"

    for ((i=0; i<20; i++)); do
        sleep 1
        grep -q "Reload is finished" <"$log_old" && break
    done

    assert_file_contains "$log_new" "CrowdSec Local API listening on 127.0.0.1:8080"
    assert_file_contains "$log_new" "Reload is finished"

    run -0 ./instance-crowdsec stop
}





