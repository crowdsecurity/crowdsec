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
    rune -0 wait-for --out "Usage of " "${CROWDSEC}" -h
    rune -0 wait-for --out "Usage of " "${CROWDSEC}" --help
}

@test "crowdsec (unknown flag)" {
    rune -0 wait-for --err "flag provided but not defined: -foobar" "$CROWDSEC" --foobar
}

@test "crowdsec (unknown argument)" {
    rune -0 wait-for --err "argument provided but not defined: trololo" "${CROWDSEC}" trololo
}

@test "crowdsec (no api and no agent)" {
    rune -0 wait-for \
        --err "You must run at least the API Server or crowdsec" \
        "${CROWDSEC}" -no-api -no-cs
}

@test "crowdsec - print error on exit" {
    # errors that cause program termination are printed to stderr, not only logs
    config_set '.db_config.type="meh"'
    rune -1 "${CROWDSEC}"
    assert_stderr --partial "unable to create database client: unknown database type 'meh'"
}

@test "crowdsec - default logging configuration (empty/missing common section)" {
    config_set '.common={}'
    rune -0 wait-for \
        --err "Starting processing data" \
        "${CROWDSEC}"
    refute_output

    config_set 'del(.common)'
    rune -0 wait-for \
        --err "Starting processing data" \
        "${CROWDSEC}"
    refute_output
}

@test "CS_LAPI_SECRET not strong enough" {
    CS_LAPI_SECRET=foo rune -1 wait-for "${CROWDSEC}"
    assert_stderr --partial "api server init: unable to run local API: controller init: CS_LAPI_SECRET not strong enough"
}

@test "crowdsec - reload (change of logfile, disabled agent)" {
    logdir1=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)
    log_old="${logdir1}/crowdsec.log"
    config_set ".common.log_dir=\"${logdir1}\""

    rune -0 ./instance-crowdsec start-pid
    PID="$output"
    assert_file_exists "$log_old"
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

    assert_file_exists "$log_new"

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

    rune -1 wait-for "${CROWDSEC}"
    assert_stderr --partial "acquis.yaml: no such file or directory"
}

@test "crowdsec (error if acquisition_path is not defined and acquisition_dir is empty)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"

    config_set '.common.log_media="stdout"'
    rune -1 wait-for "${CROWDSEC}"
    # check warning
    assert_stderr --partial "no acquisition file found"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no datasource enabled"
}

@test "crowdsec (error if acquisition_path and acquisition_dir are not defined)" {
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    rm -f "$ACQUIS_DIR"
    config_set '.crowdsec_service.acquisition_dir=""'

    config_set '.common.log_media="stdout"'
    rune -1 wait-for "${CROWDSEC}"
    # check warning
    assert_stderr --partial "no acquisition_path or acquisition_dir specified"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no datasource enabled"
}

@test "crowdsec (no error if acquisition_path is empty string but acquisition_dir is not empty)" {
    config_set '.common.log_media="stdout"'

    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    config_set '.crowdsec_service.acquisition_path=""'

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    mkdir -p "$ACQUIS_DIR"
    mv "$ACQUIS_YAML" "$ACQUIS_DIR"/foo.yaml

    rune -0 wait-for \
        --err "Starting processing data" \
        "${CROWDSEC}"

    # now, if foo.yaml is empty instead, there won't be valid datasources.

    cat /dev/null >"$ACQUIS_DIR"/foo.yaml

    rune -1 wait-for "${CROWDSEC}"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no datasource enabled"
}

@test "crowdsec (disabled datasources)" {
    if is_package_testing; then
        # we can't hide journalctl in package testing
        # because crowdsec is run from systemd
        skip "n/a for package testing"
    fi

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

    #shellcheck disable=SC2016
    rune -0 wait-for \
        --err 'datasource '\''journalctl'\'' is not available: exec: "journalctl": executable file not found in ' \
        env PATH='' "${CROWDSEC}"

    # if all datasources are disabled, crowdsec should exit

    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    rm -f "$ACQUIS_YAML"
    config_set '.crowdsec_service.acquisition_path=""'

    rune -1 wait-for env PATH='' "${CROWDSEC}"
    assert_stderr --partial "crowdsec init: while loading acquisition config: no datasource enabled"
}

@test "crowdsec -t (error in acquisition file)" {
    # we can verify the acquisition configuration without running crowdsec
    ACQUIS_YAML=$(config_get '.crowdsec_service.acquisition_path')
    config_set "$ACQUIS_YAML" 'del(.filenames)'

    # if filenames are missing, it won't be able to detect source type
    config_set "$ACQUIS_YAML" '.source="file"'
    rune -1 wait-for "${CROWDSEC}"
    assert_stderr --partial "failed to configure datasource file: no filename or filenames configuration provided"

    config_set "$ACQUIS_YAML" '.filenames=["file.log"]'
    config_set "$ACQUIS_YAML" '.meh=3'
    rune -1 wait-for "${CROWDSEC}"
    assert_stderr --partial "field meh not found in type fileacquisition.FileConfiguration"
}
