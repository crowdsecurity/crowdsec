#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    # remove trailing slash if any (like in default config.yaml from package)
    HUB_DIR=${HUB_DIR%/}
    export HUB_DIR
    DATA_DIR=$(config_get '.config_paths.data_dir')
    DETECT_YAML="$DATA_DIR/detect.yaml"
    export DETECT_YAML
    # shellcheck disable=SC2154
    TESTDATA="$BATS_TEST_DIRNAME/testdata/cscli-setup"
    export TESTDATA
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

@test "cscli setup --help" {
    rune -0 cscli help
    assert_line --regexp '^ +setup +Tools to configure crowdsec$'

    rune -0 cscli setup --help
    assert_line 'Usage:'

    # make sure that the unknown argument is not ignored and does not trigger interactive mode
    # (possibly blocking a script)
    rune -1 cscli setup blahblah
    assert_line 'Usage:'
}

@test "cscli setup detect --help" {
    rune -0 cscli setup detect --help
    assert_line 'Usage:'

    rune -1 cscli setup detect --detect-config /path/does/not/exist
    assert_stderr --partial "open /path/does/not/exist: no such file or directory"

    # - is stdin
    rune -0 cscli setup detect --detect-config - <<< "{}"
    assert_json '{setup:[]}'
    refute_stderr
}

@test "cscli setup detect (envvar CROWDSEC_SETUP_DETECT_CONFIG)" {
    export CROWDSEC_SETUP_DETECT_CONFIG="$BATS_TEST_TMPDIR"/mydetect.yaml
    rune -0 cscli setup detect --help
    assert_output --partial "path to service detection configuration, will use \$CROWDSEC_SETUP_DETECT_CONFIG if defined (default \"$CROWDSEC_SETUP_DETECT_CONFIG\")"

    rune -1 cscli setup detect
    refute_output
    assert_stderr --partial "open $CROWDSEC_SETUP_DETECT_CONFIG: no such file or directory"
}

@test "cscli setup detect (linux)" {
    # Basic OS detection.

    [[ ${OSTYPE} =~ linux.* ]] || skip
    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  linux:
	    when:
	      - Host.OS == "linux"
	    hub_spec:
	      collections:
	        - crowdsecurity/linux
	  notalinux:
	    when:
	      - Host.OS != "linux"
	EOT

    assert_json '{setup:[{detected_service:"linux",hub_spec:{collections:["crowdsecurity/linux"]}}]}'
}

@test "cscli setup detect --ignore" {
    # Services listed in --ignore will be excluded from the setup file, even if detected.

    rune -0 cscli setup detect --ignore always --ignore anotherone --detect-config - <<-EOT
	detect:
	  always:
	  anotherone:
	  foobarbaz:
	EOT

    assert_json '{setup:[{detected_service:"foobarbaz"}]}'
}

@test "cscli setup detect --list-supported-services" {
    # List all services potentially detected by the configuration file.

    rune -0 cscli setup detect --list-supported-services --detect-config - <<-EOT
	detect:
	  thewiz:
	  foobarbaz:
	  apache2:
	EOT

    # the service list is sorted
    assert_output - <<-EOT
	apache2
	foobarbaz
	thewiz
	EOT

    rune -1 cscli setup detect --list-supported-services --detect-config - <<-EOT
	thisisajoke
	EOT

    assert_stderr --partial "yaml: unmarshal errors:"
}

@test "cscli setup detect (systemctl)" {
    # Detect a service through the presence of a systemd unit.

    # shellcheck disable=SC2030
    PATH="$TESTDATA:$PATH"

    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  apache2:
	    when:
	      - Systemd.UnitInstalled("mock-apache2.service")
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	EOT

    rune -0 jq -c '.setup' <(output)

    PATH="${PATH/${TESTDATA}:/}"
}

@test "cscli setup detect (skip systemd)" {
    # Skip detection of services through systemd units.

    #shellcheck disable=SC2031
    PATH="$BATS_TEST_TMPDIR:$PATH"

    rune -0 cscli setup detect --skip-systemd --detect-config - <<-EOT
	detect:
	  apache2:
	    when:
	      - Systemd.UnitInstalled("mock-apache2.service")
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	EOT

    # setup must not be 'null', but an empty list
    assert_json '{setup:[]}'

    PATH="${PATH/${BATS_TEST_TMPDIR}:/}"
}

@test "cscli setup detect --force" {
    # Force the detection of a service.

    cat <<-EOT >"$DETECT_YAML"
	detect:
	  apache2:
	    when:
	      - Systemd.UnitInstalled("force-apache2")
	    acquisition_spec:
	      filename: apache2.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	  apache3:
	    when:
	      - Systemd.UnitInstalled("force-apache3")
	    acquisition_spec:
	      filename: apache3.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	            type: apache3
	EOT

    rune -0 cscli setup detect --force apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{acquisition_spec:{filename:"apache2.yaml",datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache2"}}},detected_service:"apache2"}]'

    rune -0 cscli setup detect --force apache2,apache3
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{acquisition_spec:{filename:"apache2.yaml",datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}}},detected_service:"apache2"},{acquisition_spec:{filename:"apache3.yaml",datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache3"}}},detected_service:"apache3"}]'

    # --force can be specified multiple times, the order does not matter
    rune -0 cscli setup detect --force apache3 --force apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{"acquisition_spec":{"datasource":{"filename":"dummy.log","labels":{"type":"apache2"},"source":"file"},"filename":"apache2.yaml"},"detected_service":"apache2"},{"acquisition_spec":{"datasource":{"filename":"dummy.log","labels":{"type":"apache3"},"source":"file"},"filename":"apache3.yaml"},"detected_service":"apache3"}]'

    rune -1 cscli setup detect --force something-else --force mock-doesnotexist
    assert_stderr --partial "Error: cscli setup detect: parsing $DETECT_YAML: could not find the following services: [mock-doesnotexist something-else], please check the service detection rules"
}

@test "cscli setup detect (process)" {
    # Detect a service from the presense of a named process.

    # This is harder to mock, because gopsutil requires proc/ to be a mount
    # point. So we pick a process that exists for sure.
    expected_process=cscli

    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  crowdsec-cli:
	    when:
	      - System.ProcessRunning("$expected_process")
	  apache3:
	    when:
	      - System.ProcessRunning("this-does-not-exist")
	EOT

    rune -0 jq -cS '.setup' <(output)
    assert_json '[{detected_service:"crowdsec-cli"}]'
}

@test "cscli setup detect (acquisition only, no hub items)" {
    # A service can require an acquisition file without requiring any collection or other hub items.

    rune -0 cscli setup detect --force apache2 --detect-config - <<-EOT
	detect:
	  apache2:
	    when:
	      - Systemd.UnitInstalled("force-apache2")
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	EOT

    rune -0 jq -cS '.setup' <(output)
    assert_json '[{"acquisition_spec":{"datasource":{"filename":"dummy.log","labels":{"type":"apache2"},"source":"file"},"filename":"apache.yaml"},"detected_service":"apache2"}]'
}

@test "cscli setup detect (yaml output)" {
    # Generate the setup file in YAML format.

    rune -0 cscli setup detect --force apache2 --yaml --detect-config - <<-EOT
	detect:
	  apache2:
	    when:
	      - Systemd.UnitInstalled("force-apache2")
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	EOT

    assert_output - <<-EOT
	setup:
	  - detected_service: apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        filename: dummy.log
	        labels:
	          type: apache2
	        source: file
	EOT
}

@test "cscli setup detect (full acquisition section)" {
    # All the acquisition options are supported an copied as-is.

    rune -0 cscli setup detect --yaml --detect-config - <<-EOT
	detect:
	  foobar:
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        filenames:
	          - /path/to/log/*.log
	        exclude_regexps:
	          - ^/path/to/log/excludeme\.log$
	        force_inotify: true
	        mode: tail
	        source: file
	        labels:
	          type: foolog
	EOT

    assert_output - <<-EOT
	setup:
	  - detected_service: foobar
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        exclude_regexps:
	          - ^/path/to/log/excludeme\.log$
	        filenames:
	          - /path/to/log/*.log
	        force_inotify: true
	        labels:
	          type: foolog
	        mode: tail
	        source: file
	EOT
}

@test "cscli setup detect + acquis + hub (no datasource or hub items)" {
    # No-op edge case, to make sure we don't crash.

    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  always:
	EOT

    assert_json '{setup:[{detected_service:"always"}]}'
    setup=$output
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<<"$setup"
    rune -0 cscli setup install-hub - <<<"$setup"
}

@test "cscli setup detect unattended (no datasource or hub items)" {
    # No-op edge case, to make sure we don't crash.

    rune -0 cscli setup unattended --detect-config - <<-EOT
	detect:
	  always:
	EOT


    assert_output <<-EOT
	
	The following services will be configured.
	- always
	
	Nothing to install or remove.
	EOT
    refute_stderr
}

@test "cscli setup detect (with hub items)" {
    # Detect service and install the corresponding collections.

    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  foobar:
	    hub_spec:
	      collections:
	        - crowdsecurity/foobar
	  apache2:
	    hub_spec:
	      collections:
	        - crowdsecurity/apache2
	EOT

    rune -0 jq -Sc '.setup | sort' <(output)
    assert_json '[{hub_spec:{collections:["crowdsecurity/apache2"]},detected_service:"apache2"},{hub_spec:{collections:["crowdsecurity/foobar"]},detected_service:"foobar"}]'
}

@test "cscli setup detect (unknown item type)" {
    # We can reference hub types that are not (yet?) known to this executable.

    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  foobar:
	    hub_spec:
	      barbapapa:
	        - crowdsecurity/foobar
	EOT

    rune -0 jq -Sc '.setup | sort' <(output)
    assert_json '[{hub_spec:{barbapapa:["crowdsecurity/foobar"]},detected_service:"foobar"}]'
}

@test "cscli setup detect (default detect.yaml)" {
    rune -0 cscli setup detect
    refute_stderr
    rune -0 cscli setup detect --list-supported-services
    refute_stderr
    assert_line 'linux'
}

@test "cscli setup detect (with acquisition)" {
    rune -0 cscli setup detect --detect-config - <<-EOT
	detect:
	  foobar:
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        source: file
	        labels:
	          type: foobar
	        filenames:
	          - /var/log/apache2/*.log
	          - /var/log/*http*/*.log
	EOT

    rune -0 yq -op '.setup | sort_keys(..)' <(output)
    assert_output - <<-EOT
	0.acquisition_spec.datasource.filenames.0 = /var/log/apache2/*.log
	0.acquisition_spec.datasource.filenames.1 = /var/log/*http*/*.log
	0.acquisition_spec.datasource.labels.type = foobar
	0.acquisition_spec.datasource.source = file
	0.acquisition_spec.filename = foo.yaml
	0.detected_service = foobar
	EOT
}

@test "cscli setup detect (datasource validation)" {
    # Minimal validation of the acquisition spec, like required fields.

    rune -1 cscli setup detect --detect-config - <<-EOT
	detect:
	  foobar:
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        labels:
	          type: something
	EOT

    assert_stderr --partial "Error: cscli setup detect: parsing <stdin>: invalid acquisition spec for foobar: source field is required"

    # more datasource-specific tests are in detect_test.go
}

@test "cscli setup install-hub (dry run: single collection)" {
    # Dry run mode of "cscli setup install-hub".

    # it's not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)

    # we "install" it
    rune -0 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["crowdsecurity/apache2"]}}]}'
    assert_line --regexp 'download collections:crowdsecurity/apache2'
    assert_line --regexp 'enable collections:crowdsecurity/apache2'

    # still not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)

    # same with dependencies
    rune -0 cscli collections remove --all
    rune -0 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["crowdsecurity/linux"]}}]}'
    assert_line --regexp 'enable collections:crowdsecurity/linux'
}

@test "cscli setup install-hub (missing hub item)" {
    # a missing item does not prevent the others from being installed
    rune -0 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["foo/bar", "crowdsecurity/caddy"]}}]}'
    assert_output --partial "download collections:crowdsecurity/caddy"
    assert_output --partial "enable collections:crowdsecurity/caddy"
    assert_stderr --regexp "Could not find .*collections:foo/bar.* in hub index, skipping install"

    rune -0 cscli setup install-hub - <<< '{"setup":[{"hub_spec":{"collections":["foo/bar", "crowdsecurity/caddy"]}}]}'
    assert_output --partial "downloading collections:crowdsecurity/caddy"
    assert_output --partial "enabling collections:crowdsecurity/caddy"
    assert_stderr --regexp "Could not find .*collections:foo/bar.* in hub index, skipping install"
}

@test "cscli setup install-hub (dry run: install multiple collections, parsers, scenarios, postoverflows)" {
    # Dry run mode of "cscli setup install-hub", with more stuff.

    rune -0 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["crowdsecurity/aws-console","crowdsecurity/caddy"],"parsers":["crowdsecurity/asterisk-logs"],"scenarios":["crowdsecurity/smb-bf"],"postoverflows":["crowdsecurity/cdn-whitelist","crowdsecurity/rdns"]}}]}'
    assert_line --regexp 'enable collections:crowdsecurity/aws-console'
    assert_line --regexp 'enable collections:crowdsecurity/caddy'
    assert_line --regexp 'enable parsers:crowdsecurity/asterisk-logs'
    assert_line --regexp 'enable scenarios:crowdsecurity/smb-bf'
    assert_line --regexp 'enable postoverflows:crowdsecurity/cdn-whitelist'
    assert_line --regexp 'enable postoverflows:crowdsecurity/rdns'
}

@test "cscli setup install-hub (missing arguments or directory)" {
    rune -1 cscli setup install-acquisition
    assert_output --partial "Usage:"
    assert_stderr --partial "Error: cscli setup install-acquisition: accepts 1 arg(s), received 0"

    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR/does/not/exist" - <<< '{setup:}'

    # empty file does not trigger directory error
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR/does/not/exist" - <<< '{}'

    # of course it must be a directory

    touch "$BATS_TEST_TMPDIR/notadir"

    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR/notadir" - <<-EOT
	setup:
	  - detected_service: apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filenames:
	          - /var/log/apache2/*.log
	EOT

    assert_stderr --partial "Error: cscli setup install-acquisition: creating acquisition directory: mkdir $BATS_TEST_TMPDIR/notadir: not a directory"
}

@test "cscli setup install-acquisition (single service)" {
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/apache2/*.log
	          - /var/log/*http*/*.log
	          - /var/log/httpd/*.log
	EOT

    # remove marker
    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.apache.yaml"
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	source: file
	EOT
}

@test "cscli setup install-acquisition (missing or bad filename)" {
    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/apache2/*.log
	EOT

    assert_stderr --partial "Error: cscli setup install-acquisition: invalid acquisition spec (0): a filename for the datasource configuration is required"

    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      filename: 
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/apache2/*.log
	EOT

    assert_stderr --partial "Error: cscli setup install-acquisition: invalid acquisition spec (0): a filename for the datasource configuration is required"

    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      filename: apache2/apache2.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/apache2/*.log
	          - /var/log/*http*/*.log
	          - /var/log/httpd/*.log
	EOT

    assert_stderr --partial "Error: cscli setup install-acquisition: invalid acquisition spec (0): acquisition filename must not contain slashes (/) or backslashes (\\)"
}

@test "cscli setup install-acquisition (multiple services)" {
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - detected_service: apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/apache2/*.log
	          - /var/log/*http*/*.log
	          - /var/log/httpd/*.log
	  - detected_service: foobar
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        source: file
	        labels:
	          type: foobar
	        filenames:
	          - /var/log/foobar/*.log
	  - detected_service: barbaz
	    acquisition_spec:
	      filename: bar.yaml
	      datasource:
	        source: file
	        labels:
	          type: barbaz
	        filenames:
	          - /path/to/barbaz.log
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.apache.yaml"
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	source: file
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.foo.yaml"
    assert_output - <<-EOT
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	source: file
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.bar.yaml"
    assert_output - <<-EOT
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	source: file
	EOT
}

@test "cscli setup install-acquisition (incorrect)" {
    # the datasource is validated according to its type.

    rune -1 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - detected_service: apache2
	    hub_spec:
	      collections:
	        - crowdsecurity/apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: docker
	        labels:
	          type: apache2
	        somethingdifferent: xyz
	EOT

    assert_stderr --partial 'Error: cscli setup install-acquisition: invalid acquisition spec (0): while parsing DockerAcquisition configuration: [3:1] unknown field "somethingdifferent"'
}

@test "cscli setup install-acquisition (key order)" {
    # keys are sorted when creating the acquisition file.
    # we should preserve the same order as in detect.yaml, but it's tricky with the current parsers

    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - detected_service: docker
	    acquisition_spec:
	      filename: docker.yaml
	      datasource:
	        source: docker
	        labels:
	          type: docker
	        follow_stderr: true
	        use_container_labels: true
	        follow_stdout: true
	        check_interval: "2 minutes"
	EOT

    # keys are sorted.

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.docker.yaml"
    assert_output - <<-EOT
	check_interval: 2 minutes
	follow_stderr: true
	follow_stdout: true
	labels:
	  type: docker
	source: docker
	use_container_labels: true
	EOT
}

@test "cscli setup install-acquisition (auto-generated file marker)" {
    # The acquisition file has a marker in a top-level comment, to indicate it was generated by cscli setup.

    marker='generated by "cscli setup"'

    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_FILE_TMPDIR" - <<-EOT
	setup:
	  - detected_service: something
	    acquisition_spec:
	      filename: something.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/something.log
	EOT

    rune -0 cat "$BATS_FILE_TMPDIR/setup.something.yaml"
    rune -0 yq 'head_comment' <(output)
    assert_output --partial "$marker"
}

@test "cscli setup install-acquisition (detect twice and overwrite)" {
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      filename: test.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - file1.yaml
	EOT

    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - acquisition_spec:
	      filename: test.yaml
	      datasource:
	        source: file
	        labels:
	          type: syslog
	        filenames:
	          - file2.yaml
	EOT

    # remove marker
    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.test.yaml"
    assert_output - <<-EOT
	filenames:
	  - file2.yaml
	labels:
	  type: syslog
	source: file
	EOT
}

@test "cscli setup (journalctl filter)" {
    rune -0 cscli setup detect --force thewiz --detect-config - <<-EOT
	detect:
	  thewiz:
	    when:
	      - Systemd.UnitInstalled("thewiz.service")
	    acquisition_spec:
	      filename: thewiz.yaml
	      datasource:
	        source: journalctl
	        labels:
	          type: thewiz
	        journalctl_filter:
	          - "SYSLOG_IDENTIFIER=TheWiz"
	EOT

    rune -0 jq -cS '.' <(output)
    assert_json '{"setup":[{"acquisition_spec":{"datasource":{"journalctl_filter":["SYSLOG_IDENTIFIER=TheWiz"],"labels":{"type":"thewiz"},"source":"journalctl"},"filename":"thewiz.yaml"},"detected_service":"thewiz"}]}'
    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" <(output)

    rune -0 cat "$BATS_TEST_TMPDIR/setup.thewiz.yaml"
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	journalctl_filter:
	  - SYSLOG_IDENTIFIER=TheWiz
	labels:
	  type: thewiz
	source: journalctl
	EOT
}

@test "cscli setup unattended" {
    # The command supports the same flags as "detect" and "install-acquisition"

    # make sure the configuration is clean
    rune -0 rm -f "$(config_get '.crowdsec_service.acquisition_path')"

    rune -0 cscli setup unattended --force smb --acquis-dir "$BATS_TEST_TMPDIR" --detect-config - <<-EOT
	detect:
	  smb:
	    when:
	      - Systemd.UnitInstalled("smb.service")
	    hub_spec:
	      collections:
	        - crowdsecurity/smb
	    acquisition_spec:
	      filename: smb.yaml
	      datasource:
	        source: file
	        filenames:
	          - /path/to/smb.log
	        labels:
	          type: smb
	EOT

    assert_output --partial "enabling collections:crowdsecurity/smb"
    assert_output --partial "creating $BATS_TEST_TMPDIR/setup.smb.yaml"
    rune -0 cscli collections inspect crowdsecurity/smb -o json
    rune -0 jq -c '.installed' <(output)
    assert_output "true"
    rune -0 cat "$BATS_TEST_TMPDIR/setup.smb.yaml"
    assert_output --partial "/path/to/smb.log"
}

@test "cscli setup unattended (disabled via envvar)" {
    CROWDSEC_SETUP_UNATTENDED_DISABLE=x rune -0 cscli setup unattended
    assert_output --partial "Unattended setup is disabled (CROWDSEC_SETUP_UNATTENDED_DISABLE is set)."
    refute_stderr

    CROWDSEC_SETUP_UNATTENDED_DISABLE= rune -0 cscli setup unattended
    refute_output --partial "Unattended setup is disabled"
    refute_stderr
}

@test "cscli setup unattended (default acquis-dir)" {
    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')

    rune -0 rm -f "$(config_get '.crowdsec_service.acquisition_path')"

    rune -0 cscli setup unattended --acquis-dir "$ACQUIS_DIR" --detect-config - <<-EOT
	detect:
	  always:
	    acquisition_spec:
	      filename: always.yaml
	      datasource:
	        source: file
	        filenames:
	          - /path/to/something.log
	EOT

    assert_output --partial "creating $ACQUIS_DIR/setup.always.yaml"
    rune -0 cat "$ACQUIS_DIR/setup.always.yaml"
    assert_output --partial "/path/to/something.log"
}

@test "cscli setup unattended (create acquisition directory)" {
    ACQUIS_DIR="$BATS_TEST_TMPDIR/acquis.d"
    rune -0 rm -f "$(config_get '.crowdsec_service.acquisition_path')"

    rune -0 cscli setup unattended --acquis-dir "$ACQUIS_DIR" --detect-config - <<-EOT
	detect:
	  always:
	    acquisition_spec:
	      filename: always.yaml
	      datasource:
	        source: file
	        filenames:
	          - /path/to/something.log
	EOT

    assert_dir_exists "$ACQUIS_DIR"

    rune -0 touch "$ACQUIS_DIR"2
    rune -1 cscli setup unattended --acquis-dir "$ACQUIS_DIR"2 --detect-config - <<-EOT
	detect:
	  always:
	    acquisition_spec:
	      filename: always.yaml
	      datasource:
	        source: file
	        filenames:
	          - /path/to/something.log
	EOT

    assert_stderr --partial "Error: cscli setup unattended: creating acquisition directory: mkdir ${ACQUIS_DIR}2: not a directory"
}

@test "cscli setup validate" {
    # an empty file is not enough
    rune -1 cscli setup validate /dev/null
    assert_stderr --partial "EOF"
    assert_stderr --partial "invalid setup file"

    # this is ok; install nothing
    rune -0 cscli setup validate - <<-EOT
	setup:
	EOT
    refute_output

    rune -1 cscli setup validate --color=no - <<-EOT
	se tup:
	EOT

    assert_stderr - <<-EOT
	Error: cscli setup validate: invalid setup file: [1:1] unknown field "se tup"
	>  1 | se tup: null
	       ^
	
	EOT

    rune -1 cscli setup validate --color=no - <<-EOT
	setup:
	alsdk al; sdf
	EOT

    assert_stderr - <<-EOT
	Error: cscli setup validate: invalid setup file: [2:1] string was used where sequence is expected
	   1 | setup:
	>  2 | alsdk al; sdf
	       ^
	
	EOT

    rune -1 cscli setup validate --color=no - <<-EOT
	setup:
	  key: value1
	  key: value2
	EOT

    assert_stderr - <<-EOT
	Error: cscli setup validate: invalid setup file: [3:3] mapping key "key" already defined at [2:3]
	   1 | setup:
	   2 |   key: value1
	>  3 |   key: value2
	         ^
	
	EOT
}
