#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    # remove trailing slash if any (like in default config.yaml from package)
    HUB_DIR=${HUB_DIR%/}
    export HUB_DIR
    CONFIG_DIR=$(config_get '.config_paths.config_dir')
    DETECT_YAML="$CONFIG_DIR/detect.yaml"
    export DETECT_YAML
    # shellcheck disable=SC2154
    TESTDATA="$BATS_TEST_DIRNAME/testdata/cscli-setup"
    export TESTDATA

    export CROWDSEC_FEATURE_CSCLI_SETUP="true"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    load "../lib/bats-mock/load.bash"
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

@test "cscli setup detect (linux)" {
    # Basic OS detection.

    [[ ${OSTYPE} =~ linux.* ]] || skip
    rune -0 cscli setup detect --detect-config - <<-EOT
	version: 1.0
	detect:
	  linux:
	    when:
	      - OS.Family == "linux"
	    hub_spec:
	      collections:
	        - crowdsecurity/linux
	  notalinux:
	    when:
	      - OS.Family != "linux"
	EOT

    assert_json '{setup:[{detected_service:"linux",hub_spec:{collections:["crowdsecurity/linux"]}}]}'
}

@test "cscli setup detect --skip-service" {
    # Services listed in --skip-service will be excluded from the setup file, even if detected.

    rune -0 cscli setup detect --skip-service linux --skip-service always --detect-config - <<-EOT
	version: 1.0
	detect:
	  linux:
	    when:
	      - OS.Family == "linux"
	  notalinux:
	    when:
	      - OS.Family != "linux"
	  always:
	  foobarbaz:
	EOT

    assert_json '{setup:[{detected_service:"foobarbaz"}]}'
}

@test "cscli setup detect --force-os-*" {
    # Fake another OS. Can be used to generate setup files in a CI.

    rune -0 cscli setup detect --force-os-family linux --detect-config "$TESTDATA/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="linux")' <(output)
    assert_json '{detected_service:"linux",hub_spec:{collections:["crowdsecurity/linux"]},acquisition_spec:{filename:"linux.yaml", datasource:{source:"file",labels:{type:"syslog"},filenames:["/var/log/syslog","/var/log/kern.log","/var/log/messages"]}}}'

    rune -0 cscli setup detect --force-os-family freebsd --detect-config "$TESTDATA/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="freebsd")' <(output)
    assert_json '{detected_service:"freebsd",hub_spec:{collections:["crowdsecurity/freebsd"]}}'

    rune -0 cscli setup detect --force-os-family windows --detect-config "${TESTDATA}/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="windows")' <(output)
    assert_json '{detected_service:"windows",hub_spec:{collections:["crowdsecurity/windows"]}}'

    # unknown family is not forbidden
    rune -0 cscli setup detect --force-os-family magillagorilla --skip-systemd --detect-config "${TESTDATA}/detect.yaml"
    assert_json '{setup:[]}'

    rune -0 cscli setup detect --force-os-family linux --force-os-id redhat --detect-config - <<-EOT
	version: 1.0
	detect:
	  deb:
	    when:
	      - OS.Family == "linux"
	      - OS.ID == "debian"
	  rpm:
	    when:
	      - OS.Family == "linux"
	      - OS.ID == "redhat"
	EOT

    assert_json '{setup:[{detected_service:"rpm"}]}'

    rune -0 cscli setup detect --force-os-family linux --force-os-id ubuntu --force-os-version 5.04 --detect-config - <<-EOT
	version: 1.0
	detect:
	  warty-warthog:
	    when:
	      - OS.Family == "linux"
	      - OS.ID == "ubuntu"
	      - OS.VersionCheck("=4.10")
	  hoary-hedgehog:
	    when:
	      - OS.Family == "linux"
	      - OS.ID == "ubuntu"
	      - OS.VersionCheck("=5.04")
	  breezy-badger:
	    when:
	      - OS.Family == "linux"
	      - OS.ID == "ubuntu"
	      - OS.VersionCheck("=5.10")
	EOT

    # VersionCheck takes >=, <= or a single =
    # Can also use VersionAtLeast(), RawVersion

    assert_json '{setup:[{detected_service:"hoary-hedgehog"}]}'
}

@test "cscli setup detect --list-supported-services" {
    # List all services potentially detected by the configuration file.

    rune -0 cscli setup detect --list-supported-services --detect-config - <<-EOT
	version: 1.0
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

    # transparently mock systemctl. It's easier if you can tell the application
    # under test which executable to call (in which case just call $mock) but
    # here we do the symlink and $PATH dance as an example
    mocked_command="systemctl"

    # mock setup
    mock="$(mock_create)"
    mock_path="${mock%/*}"
    mock_file="${mock##*/}"
    ln -sf "$mock_path/$mock_file" "$mock_path/$mocked_command"

    #shellcheck disable=SC2030
    PATH="$mock_path:$PATH"

    mock_set_output "$mock" \
'UNIT FILE                               STATE   VENDOR PRESET
snap-bare-5.mount                       enabled enabled
snap-core-13308.mount                   enabled enabled
snap-firefox-1635.mount                 enabled enabled
snap-fx-158.mount                       enabled enabled
snap-gimp-393.mount                     enabled enabled
snap-gtk\x2dcommon\x2dthemes-1535.mount enabled enabled
snap-kubectl-2537.mount                 enabled enabled
snap-rustup-1027.mount                  enabled enabled
cups.path                               enabled enabled
console-setup.service                   enabled enabled
dmesg.service                           enabled enabled
getty@.service                          enabled enabled
grub-initrd-fallback.service            enabled enabled
irqbalance.service                      enabled enabled
keyboard-setup.service                  enabled enabled
mock-apache2.service                    enabled enabled
networkd-dispatcher.service             enabled enabled
ua-timer.timer                          enabled enabled
update-notifier-download.timer          enabled enabled
update-notifier-motd.timer              enabled enabled

20 unit files listed.'
    mock_set_status "$mock" 1 2

    rune -0 cscli setup detect --detect-config - <<-EOT
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("mock-apache2.service")
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	EOT

    rune -0 jq -c '.setup' <(output)

    # If a call to UnitFoundwas part of the expression and it returned true,
    # there is a default journalctl_filter derived from the unit's name.
    assert_json '[{acquisition_spec:{filename:"apache.yaml",datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}}},detected_service:"apache2"}]'

    # the command was called exactly once
    [[ $(mock_get_call_num "$mock") -eq 1 ]]

    # the command was called with the expected parameters
    [[ $(mock_get_call_args "$mock" 1) == "list-unit-files --state=enabled,generated,static" ]]

    rune -1 systemctl

    # mock teardown
    unlink "$mock_path/$mocked_command"
    PATH="${PATH/${mock_path}:/}"
}

# XXX this is the same boilerplate as the previous test, can be simplified
@test "cscli setup detect (skip systemd)" {
    # Skip detection of services through systemd units.
 
    # transparently mock systemctl. It's easier if you can tell the application
    # under test which executable to call (in which case just call $mock) but
    # here we do the symlink and $PATH dance as an example
    mocked_command="systemctl"

    # mock setup
    mock="$(mock_create)"
    mock_path="${mock%/*}"
    mock_file="${mock##*/}"
    ln -sf "$mock_path/$mock_file" "$mock_path/$mocked_command"

    #shellcheck disable=SC2031
    PATH="$mock_path:$PATH"

    # we don't really care about the output, it's not used anyway
    mock_set_output "$mock" ""
    mock_set_status "$mock" 1 2

    rune -0 cscli setup detect --skip-systemd --detect-config - <<-EOT
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("mock-apache2.service")
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

    # the command was never called
    [[ $(mock_get_call_num "$mock") -eq 0 ]]

    rune -0 systemctl

    # mock teardown
    unlink "$mock_path/$mocked_command"
    PATH="${PATH/${mock_path}:/}"
}

@test "cscli setup detect --force-unit" {
    # Fake the existence of a systemd unit.

    cat <<-EOT >"$DETECT_YAML"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
	    acquisition_spec:
	      filename: apache2.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	          type: apache2
	  apache3:
	    when:
	      - UnitFound("force-apache3")
	    acquisition_spec:
	      filename: apache3.yaml
	      datasource:
	        source: file
	        filename: dummy.log
	        labels:
	            type: apache3
	EOT

    rune -0 cscli setup detect --force-unit force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{acquisition_spec:{filename:"apache2.yaml",datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache2"}}},detected_service:"apache2"}]'

    rune -0 cscli setup detect --force-unit force-apache2,force-apache3
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{acquisition_spec:{filename:"apache2.yaml",datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}}},detected_service:"apache2"},{acquisition_spec:{filename:"apache3.yaml",datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache3"}}},detected_service:"apache3"}]'

    # force-unit can be specified multiple times, the order does not matter
    rune -0 cscli setup detect --force-unit force-apache3 --force-unit force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{"acquisition_spec":{"datasource":{"filename":"dummy.log","labels":{"type":"apache2"},"source":"file"},"filename":"apache2.yaml"},"detected_service":"apache2"},{"acquisition_spec":{"datasource":{"filename":"dummy.log","labels":{"type":"apache3"},"source":"file"},"filename":"apache3.yaml"},"detected_service":"apache3"}]'

    rune -1 cscli setup detect --force-unit mock-doesnotexist
    assert_stderr --partial "Error: parsing $DETECT_YAML: unit(s) required but not supported: [mock-doesnotexist]"
}

@test "cscli setup detect (process)" {
    # Detect a service from the presense of a named process.

    # This is harder to mock, because gopsutil requires proc/ to be a mount
    # point. So we pick a process that exists for sure.
    expected_process=cscli

    rune -0 cscli setup detect --detect-config - <<-EOT
	version: 1.0
	detect:
	  crowdsec-cli:
	    when:
	      - ProcessRunning("$expected_process")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    rune -0 jq -cS '.setup' <(output)
    assert_json '[{detected_service:"crowdsec-cli"}]'
}

@test "cscli setup detect --force-process" {
    # Fake the existence of a named process.

    rune -0 cscli setup detect --force-process force-apache2 --detect-config - <<-EOT
	version: 1.0
	detect:
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    rune -0 jq -cS '.setup' <(output)
    assert_json '[{detected_service:"apache2"}]'
}

@test "cscli setup detect (acquisition only, no hub items)" {
    # A service can require an acquisition file without requiring any collection or other hub items.

    rune -0 cscli setup detect --force-unit force-apache2 --detect-config - <<-EOT
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
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

    rune -0 cscli setup detect --force-unit force-apache2 --yaml --detect-config - <<-EOT
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
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
	version: 1.0
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
	version: 1.0
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
	version: 1.0
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

    rune -0 cscli setup detect --force-process force-apache2,force-foobar --detect-config - <<-EOT
	version: 1.0
	detect:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
	    hub_spec:
	      collections:
	        - crowdsecurity/foobar
	  qox:
	    when:
	      - ProcessRunning("test-qox")
	    hub_spec:
	      collections:
	        - crowdsecurity/foobar
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
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
	version: 1.0
	detect:
	  foobar:
	    hub_spec:
	      barbapapa:
	        - crowdsecurity/foobar
	EOT

    rune -0 jq -Sc '.setup | sort' <(output)
    assert_json '[{hub_spec:{barbapapa:["crowdsecurity/foobar"]},detected_service:"foobar"}]'
}

@test "cscli setup detect (with acquisition)" {
    rune -0 cscli setup detect --force-process force-foobar --detect-config - <<-EOT
	version: 1.0
	detect:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
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

    rune -1 cscli setup detect --force-process mock-doesnotexist
    assert_stderr --partial "Error: parsing $DETECT_YAML: process(es) required but not supported: [mock-doesnotexist]"
}

@test "cscli setup detect (datasource validation)" {
    # Minimal validation of the acquisition spec, like required fields.

    rune -1 cscli setup detect --detect-config - <<-EOT
	version: 1.0
	detect:
	  foobar:
	    acquisition_spec:
	      filename: foo.yaml
	      datasource:
	        labels:
	          type: something
	EOT

    assert_stderr --partial "Error: parsing <stdin>: invalid acquisition spec for foobar: source is empty"

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

@test "cscli setup install-hub (dry run: install multiple collections, parsers, scenarios, postoverflows)" {
    # Dry run mode of "cscli setup install-hub", with more stuff.

    rune -0 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["crowdsecurity/aws-console","crowdsecurity/caddy"],"parsers":["crowdsecurity/asterisk-logs"],"scenarios":["crowdsecurity/smb-bf"],"postoverflows":["crowdsecurity/cdn-whitelist","crowdsecurity/rdns"]}}]}'
    assert_line --regexp 'enable collections:crowdsecurity/aws-console'
    assert_line --regexp 'enable collections:crowdsecurity/caddy'
    assert_line --regexp 'enable parsers:crowdsecurity/asterisk-logs'
    assert_line --regexp 'enable scenarios:crowdsecurity/smb-bf'
    assert_line --regexp 'enable postoverflows:crowdsecurity/cdn-whitelist'
    assert_line --regexp 'enable postoverflows:crowdsecurity/rdns'

    rune -1 cscli setup install-hub - --dry-run <<< '{"setup":[{"hub_spec":{"collections":["crowdsecurity/foo"]}}]}'
    assert_stderr --partial 'Error: item collections:crowdsecurity/foo not found'
}

@test "cscli setup install-hub (missing arguments or directory)" {
    rune -1 cscli setup install-acquisition
    assert_output --partial "Usage:"
    assert_stderr --partial "Error: accepts 1 arg(s), received 0"

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
	        filenames:
	          - /var/log/apache2/*.log
	EOT

    # XXX: the error should inclide the name of the directory, not the file
    assert_stderr --partial "Error: creating acquisition directory: mkdir $BATS_TEST_TMPDIR/notadir: not a directory"
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

@test "cscli setup install-acquisition (multiple services)" {
    # multiple items
    # XXX: invalid because datasources have no Name (detected_service) for the acquisition file
    # but we don't validate them yet
    # TODO: validate ServicePlan etc.

#    rune -0 cscli setup install-acquisition - <<-EOT
#	setup:
#	  - datasource:
#	      labels:
#	        type: syslog
#	      filenames:
#	        - /var/log/apache2/*.log
#	        - /var/log/*http*/*.log
#	        - /var/log/httpd/*.log
#	  - datasource:
#	      labels:
#	        type: foobar
#	      filenames:
#	        - /var/log/foobar/*.log
#	  - datasource:
#	      labels:
#	        type: barbaz
#	      filenames:
#	        - /path/to/barbaz.log
#	EOT
#
#    rune -0 yq '. head_comment=""' <(output)
#    assert_output - <<-EOT
#	filenames:
#	  - /var/log/apache2/*.log
#	  - /var/log/*http*/*.log
#	  - /var/log/httpd/*.log
#	labels:
#	  type: syslog
#	---
#	filenames:
#	  - /var/log/foobar/*.log
#	labels:
#	  type: foobar
#	---
#	filenames:
#	  - /path/to/barbaz.log
#	labels:
#	  type: barbaz
#	EOT

    # multiple items, to a directory

    # avoid the BATS_TEST_TMPDIR variable, it can have a double //

    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - detected_service: apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
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
	        labels:
	          type: foobar
	        filenames:
	          - /var/log/foobar/*.log
	  - detected_service: barbaz
	    acquisition_spec:
	      filename: bar.yaml
	      datasource:
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
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.foo.yaml"
    assert_output - <<-EOT
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.bar.yaml"
    assert_output - <<-EOT
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	EOT
}

@test "cscli setup install-acquisition (multiple items, incorrect acquisition)" {
    # Having both filenames and journalctl does not generate two files: the datasource is copied as-is, even if incorrect.

    rune -0 cscli setup install-acquisition --acquis-dir "$BATS_TEST_TMPDIR" - <<-EOT
	setup:
	  - detected_service: apache2
	    hub_spec:
	      collections:
	        - crowdsecurity/apache2
	    acquisition_spec:
	      filename: apache.yaml
	      datasource:
	        labels:
	          type: apache2
	        filenames:
	          - /var/log/apache2/*.log
	          - /var/log/*http*/*.log
	          - /var/log/httpd/*.log
	        journalctl_filter:
	          - _SYSTEMD_UNIT=apache2.service
	EOT

    rune -0 yq '. head_comment=""' < "$BATS_TEST_TMPDIR/setup.apache.yaml"
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	journalctl_filter:
	  - _SYSTEMD_UNIT=apache2.service
	labels:
	  type: apache2
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
	        labels:
	          type: syslog
	        filenames:
	          - /var/log/something.log
	EOT

    rune -0 cat "$BATS_FILE_TMPDIR/setup.something.yaml"
    rune -0 yq 'head_comment' <(output)
    assert_output --partial "$marker"
}

@test "cscli setup (custom journalctl filter)" {
    rune -0 cscli setup detect --force-unit thewiz.service --detect-config - <<-EOT
	version: 1.0
	detect:
	  thewiz:
	    when:
	      - UnitFound("thewiz.service")
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

    rune -0 cscli setup unattended --force-unit smb.service --acquis-dir "$BATS_TEST_TMPDIR" --detect-config - <<-EOT
	version: 1.0
	detect:
	  smb:
	    when:
	      - UnitFound("smb.service")
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


@test "cscli setup unattended (default acquis-dir)" {
    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')

    rune -0 rm -f "$(config_get '.crowdsec_service.acquisition_path')"

    rune -0 cscli setup unattended --acquis-dir "$ACQUIS_DIR" --detect-config - <<-EOT
	version: 1.0
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
	version: 1.0
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
	version: 1.0
	detect:
	  always:
	    acquisition_spec:
	      filename: always.yaml
	      datasource:
	        source: file
	        filenames:
	          - /path/to/something.log
	EOT

    assert_stderr --partial "Error: creating acquisition directory: mkdir ${ACQUIS_DIR}2: not a directory"
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
	[1:1] unknown field "se tup"
	>  1 | se tup: null
	       ^
	
	Error: invalid setup file
	EOT

    rune -1 cscli setup validate --color=no - <<-EOT
	setup:
	alsdk al; sdf
	EOT

    assert_stderr - <<-EOT
	[2:1] string was used where sequence is expected
	   1 | setup:
	>  2 | alsdk al; sdf
	       ^
	
	Error: invalid setup file
	EOT
}
