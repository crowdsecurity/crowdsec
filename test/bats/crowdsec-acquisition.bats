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

@test "malformed acquisition file" {
    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	filename:
	- /path/to/file.log
	labels:
	  type: syslog
	EOT

    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "crowdsec init: while loading acquisition config: configuring datasource of type file from $ACQUIS_DIR/file.yaml (position 0): cannot parse FileAcquisition configuration: [2:1] cannot unmarshal []interface {} into Go struct field Configuration.Filename of type string"
}

@test "empty acquisition file" {
    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	EOT

    rune -0 "$CROWDSEC" -t
}

@test "malformed acquisition file (missing keys)" {
    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	labels:
	  type: syslog
	EOT

    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "crowdsec init: while loading acquisition config: missing 'source' field in $ACQUIS_DIR/file.yaml (position 0)"
}

@test "malformed acquisition file (duplicate key)" {
    cat >"$ACQUIS_DIR/file.yaml" <<-EOT
	filename:
	- /path/to/file.log
	filename:
	- /path/to/file.log
	EOT

    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "crowdsec init: while loading acquisition config: failed to parse $ACQUIS_DIR/file.yaml: position 0: [3:1] mapping key \"filename\" already defined at [1:1]"
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

    rune -0 "$CROWDSEC" -t
    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/file.yaml (position 0): detected 'source=file'"
    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/file.yaml (position 1): detected 'source=file'"

    rm -f  "$ACQUIS_DIR/file.yaml"

    cat >"$ACQUIS_DIR"/journal.yaml <<-EOT
	journalctl_filter:
	 - "_SYSTEMD_UNIT=ssh.service"
	labels:
	  type: syslog
	EOT

    rune -0 "$CROWDSEC" -t

    assert_stderr --partial "datasource type missing in $ACQUIS_DIR/journal.yaml (position 0): detected 'source=journalctl'"

    rm -f  "$ACQUIS_DIR/journal.yaml"

    # However, a wrong source type will raise a brow.
    # This is currently not a fatal error because it has been tolerated in the past.

    cat >"$ACQUIS_DIR"/bad.yaml <<-EOT
	source: docker
	journalctl_filter:
	 - "_SYSTEMD_UNIT=ssh.service"
	labels:
	  type: syslog
	EOT

    rune -1 "$CROWDSEC" -t

    assert_stderr --partial "crowdsec init: while loading acquisition config: configuring datasource of type docker from $ACQUIS_DIR/bad.yaml (position 0): while parsing DockerAcquisition configuration: [2:1] unknown field \\\"journalctl_filter\\\""
}

@test "datasource docker (regexp)" {
    cat >"$ACQUIS_DIR"/bad.yaml <<-EOT
	source: docker
	container_name_regexp:
	  - "[abc"
	labels:
	  type: syslog
	EOT

    rune -1 "$CROWDSEC" -t
    assert_stderr --partial "crowdsec init: while loading acquisition config: configuring datasource of type docker from $ACQUIS_DIR/bad.yaml (position 0): container_name_regexp: error parsing regexp: missing closing ]: \`[abc\`"
}

@test "test mode does not fail because of appsec and allowlists" {
    rune -0 cscli collections install crowdsecurity/appsec-virtual-patching
    cat >"$ACQUIS_DIR/appsec.yaml" <<-EOT
	source: appsec
	appsec_config: crowdsecurity/virtual-patching
	labels:
	  type: appsec
	EOT

    config_set '.common.log_media="stdout"'

    rune -0 "$CROWDSEC" -t --trace

    assert_stderr --partial "Configuration test done"
}
