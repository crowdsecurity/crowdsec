#!/usr/bin/env bats

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
    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    mkdir -p "$ACQUIS_DIR"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "malformed acqusition file" {
    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	filename:
	- /path/to/file.log
	labels:
	  type: syslog
	EOT

    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "crowdsec init: while loading acquisition config: while configuring datasource of type file from $ACQUIS_DIR/file.yaml (position 0): cannot parse FileAcquisition configuration: yaml: unmarshal errors:"
}

@test "datasource type detection" {
    config_set '.common.log_level="debug" | .common.log_media="stdout"'

    # for backward compatibility, a missing source type is not a problem if it can be detected by the presence of other fields

    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	filename: /path/to/file.log
	labels:
	  type: syslog
	---
	filenames:
	 - /path/to/file.log
	labels:
	  type: syslog
	EOT

    cat >"$ACQUIS_DIR"/journal.yaml <<-EOT
	journalctl_filter:
	 - "_SYSTEMD_UNIT=ssh.service"
	labels:
	  type: syslog
	EOT

    # However, a wrong source type will raise a brow.
    # This is currently not a fatal error because it has been tolerated in the past.

    cat >"$ACQUIS_DIR"/bad.yaml <<-EOT
	source: docker
	journalctl_filter:
	 - "_SYSTEMD_UNIT=ssh.service"
	labels:
	  type: syslog
	EOT

    rune -0 "$CROWDSEC" -t
    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/file.yaml (position 0): detected 'source=file'"
    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/file.yaml (position 1): detected 'source=file'"
    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/journal.yaml (position 0): detected 'source=journalctl'"
    assert_stderr --partial "datasource type mismatch in $ACQUIS_DIR/bad.yaml (position 0): found 'docker' but should probably be 'journalctl'"
}
