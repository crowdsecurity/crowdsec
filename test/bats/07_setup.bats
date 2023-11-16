#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    # remove trailing slash if any (like in default config.yaml from package)
    HUB_DIR=${HUB_DIR%/}
    export HUB_DIR
    DETECT_YAML="${HUB_DIR}/detect.yaml"
    export DETECT_YAML
    # shellcheck disable=SC2154
    TESTDATA="${BATS_TEST_DIRNAME}/testdata/07_setup"
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

#shellcheck disable=SC2154
@test "cscli setup" {
    rune -0 cscli help
    assert_line --regexp '^ +setup +Tools to configure crowdsec$'

    rune -0 cscli setup --help
    assert_line 'Usage:'
    assert_line '  cscli setup [command]'
    assert_line 'Manage hub configuration and service detection'
    assert_line --partial "detect                  detect running services, generate a setup file"
    assert_line --partial "datasources             generate datasource (acquisition) configuration from a setup file"
    assert_line --partial "install-hub             install items from a setup file"
    assert_line --partial "validate                validate a setup file"

    # cobra should return error for non-existing sub-subcommands, but doesn't
    rune -0 cscli setup blahblah
    assert_line 'Usage:'
}

@test "cscli setup detect --help; --detect-config" {
    rune -0 cscli setup detect --help
    assert_line --regexp "detect running services, generate a setup file"
    assert_line 'Usage:'
    assert_line '  cscli setup detect [flags]'
    assert_line --partial "--detect-config string      path to service detection configuration (default \"${HUB_DIR}/detect.yaml\")"
    assert_line --partial "--force-process strings     force detection of a running process (can be repeated)"
    assert_line --partial "--force-unit strings        force detection of a systemd unit (can be repeated)"
    assert_line --partial "--list-supported-services   do not detect; only print supported services"
    assert_line --partial "--force-os-family string    override OS.Family: one of linux, freebsd, windows or darwin"
    assert_line --partial "--force-os-id string        override OS.ID=[debian | ubuntu | , redhat...]"
    assert_line --partial "--force-os-version string   override OS.RawVersion (of OS or Linux distribution)"
    assert_line --partial "--skip-service strings      ignore a service, don't recommend hub/datasources (can be repeated)"

    rune -1 cscli setup detect --detect-config /path/does/not/exist
    assert_stderr --partial "open /path/does/not/exist: no such file or directory"

    # - is stdin
    rune -1 cscli setup detect --detect-config - <<< "{}"
    assert_stderr --partial "detecting services: missing version tag (must be 1.0)"

    # rm -f "${HUB_DIR}/detect.yaml"
}

@test "cscli setup detect (linux), --skip-service" {
    [[ ${OSTYPE} =~ linux.* ]] || skip
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	detect:
	  linux:
	    when:
	      - OS.Family == "linux"
	    install:
	      collections:
	        - crowdsecurity/linux
	  thewiz:
	    when:
	      - OS.Family != "linux"
	  foobarbaz:
	EOT

    rune -0 cscli setup detect --detect-config "$tempfile"
    assert_json '{setup:[{detected_service:"foobarbaz"},{detected_service:"linux",install:{collections:["crowdsecurity/linux"]}}]}'

    rune -0 cscli setup detect --detect-config "$tempfile" --skip-service linux
    assert_json '{setup:[{detected_service:"foobarbaz"}]}'
}

@test "cscli setup detect --force-os-*" {
    rune -0 cscli setup detect --force-os-family linux --detect-config "${TESTDATA}/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="linux")' <(output)
    assert_json '{detected_service:"linux",install:{collections:["crowdsecurity/linux"]},datasource:{source:"file",labels:{type:"syslog"},filenames:["/var/log/syslog","/var/log/kern.log","/var/log/messages"]}}'

    rune -0 cscli setup detect --force-os-family freebsd --detect-config "${TESTDATA}/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="freebsd")' <(output)
    assert_json '{detected_service:"freebsd",install:{collections:["crowdsecurity/freebsd"]}}'

    rune -0 cscli setup detect --force-os-family windows --detect-config "${TESTDATA}/detect.yaml"
    rune -0 jq -cS '.setup[] | select(.detected_service=="windows")' <(output)
    assert_json '{detected_service:"windows",install:{collections:["crowdsecurity/windows"]}}'

    rune -0 cscli setup detect --force-os-family darwin --detect-config "${TESTDATA}/detect.yaml"

    # XXX do we want do disallow unknown family?
    # assert_stderr --partial "detecting services: OS 'darwin' not supported"

    # XXX TODO force-os-id, force-os-version
}

@test "cscli setup detect --list-supported-services" {
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	detect:
	  thewiz:
	  foobarbaz:
	  apache2:
	EOT

    rune -0 cscli setup detect --list-supported-services --detect-config "$tempfile"
    # the service list is sorted
    assert_output - <<-EOT
	apache2
	foobarbaz
	thewiz
	EOT

    cat <<-EOT >"${tempfile}"
	thisisajoke
	EOT

    rune -1 cscli setup detect --list-supported-services --detect-config "$tempfile"
    assert_stderr --partial "yaml: unmarshal errors:"

    rm -f "$tempfile"
}

@test "cscli setup detect (systemctl)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("mock-apache2.service")
	    datasource:
	      source: file
	      filename: dummy.log
	      labels:
	        type: apache2
	EOT

    # transparently mock systemctl. It's easier if you can tell the application
    # under test which executable to call (in which case just call $mock) but
    # here we do the symlink and $PATH dance as an example
    mocked_command="systemctl"

    # mock setup
    mock="$(mock_create)"
    mock_path="${mock%/*}"
    mock_file="${mock##*/}"
    ln -sf "${mock_path}/${mock_file}" "${mock_path}/${mocked_command}"

    #shellcheck disable=SC2030
    PATH="${mock_path}:${PATH}"

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

    rune -0 cscli setup detect
    rune -0 jq -c '.setup' <(output)

    # If a call to UnitFoundwas part of the expression and it returned true,
    # there is a default journalctl_filter derived from the unit's name.
    assert_json '[{datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}},detected_service:"apache2"}]'

    # the command was called exactly once
    [[ $(mock_get_call_num "$mock") -eq 1 ]]

    # the command was called with the expected parameters
    [[ $(mock_get_call_args "$mock" 1) == "list-unit-files --state=enabled,generated,static" ]]

    rune -1 systemctl

    # mock teardown
    unlink "${mock_path}/${mocked_command}"
    PATH="${PATH/${mock_path}:/}"
}

# XXX this is the same boilerplate as the previous test, can be simplified
@test "cscli setup detect (snub systemd)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("mock-apache2.service")
	    datasource:
	      source: file
	      filename: dummy.log
	      labels:
	        type: apache2
	EOT

    # transparently mock systemctl. It's easier if you can tell the application
    # under test which executable to call (in which case just call $mock) but
    # here we do the symlink and $PATH dance as an example
    mocked_command="systemctl"

    # mock setup
    mock="$(mock_create)"
    mock_path="${mock%/*}"
    mock_file="${mock##*/}"
    ln -sf "${mock_path}/${mock_file}" "${mock_path}/${mocked_command}"

    #shellcheck disable=SC2031
    PATH="${mock_path}:${PATH}"

    # we don't really care about the output, it's not used anyway
    mock_set_output "$mock" ""
    mock_set_status "$mock" 1 2

    rune -0 cscli setup detect --snub-systemd

    # setup must not be 'null', but an empty list
    assert_json '{setup:[]}'

    # the command was never called
    [[ $(mock_get_call_num "$mock") -eq 0 ]]

    rune -0 systemctl

    # mock teardown
    unlink "${mock_path}/${mocked_command}"
    PATH="${PATH/${mock_path}:/}"
}

@test "cscli setup detect --force-unit" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
	    datasource:
	      source: file
	      filename: dummy.log
	      labels:
	        type: apache2
	  apache3:
	    when:
	      - UnitFound("force-apache3")
	    datasource:
	      source: file
	      filename: dummy.log
	      labels:
	        type: apache3
	EOT

    rune -0 cscli setup detect --force-unit force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache2"}},detected_service:"apache2"}]'

    rune -0 cscli setup detect --force-unit force-apache2,force-apache3
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}},detected_service:"apache2"},{datasource:{source:"file",filename:"dummy.log",labels:{"type":"apache3"}},detected_service:"apache3"}]'

    # force-unit can be specified multiple times, the order does not matter
    rune -0 cscli setup detect --force-unit force-apache3 --force-unit force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}},detected_service:"apache2"},{datasource:{source:"file",filename:"dummy.log",labels:{type:"apache3"}},detected_service:"apache3"}]'

    rune -1 cscli setup detect --force-unit mock-doesnotexist
    assert_stderr --partial "detecting services: unit(s) forced but not supported: [mock-doesnotexist]"
}

@test "cscli setup detect (process)" {
    # This is harder to mock, because gopsutil requires proc/ to be a mount
    # point. So we pick a process that exists for sure.
    expected_process=cscli

    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - ProcessRunning("${expected_process}")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    rune -0 cscli setup detect
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{detected_service:"apache2"}]'
}

@test "cscli setup detect --force-process" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    rune -0 cscli setup detect --force-process force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{detected_service:"apache2"}]'
}

@test "cscli setup detect (acquisition only, no hub items)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
	    datasource:
	      source: file
	      filename: dummy.log
	      labels:
	        type: apache2
	EOT

    rune -0 cscli setup detect --force-unit force-apache2
    rune -0 jq -cS '.setup' <(output)
    assert_json '[{datasource:{source:"file",filename:"dummy.log",labels:{type:"apache2"}},detected_service:"apache2"}]'

    rune -0 cscli setup detect --force-unit force-apache2 --yaml
    assert_output - <<-EOT
	setup:
	  - detected_service: apache2
	    datasource:
	      filename: dummy.log
	      labels:
	        type: apache2
	      source: file
	EOT
}

@test "cscli setup detect (full acquisition section)" {
    skip "not supported yet"
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  foobar:
            datasource:
              filenames:
                - /path/to/log/*.log
              exclude_regexps:
                - ^/path/to/log/excludeme\.log$
              force_inotify: true
              mode: tail
              labels:
                type: foolog
	EOT

    rune -0 cscli setup detect --yaml
    assert_output - <<-EOT
	setup:
	  - detected_service: foobar
	    datasource:
              filenames:
                - /path/to/log/*.log
              exclude_regexps:
                - ^/path/to/log/excludeme.log$
              force_inotify: true
              mode: tail
              labels:
                type: foolog
	EOT
}

@test "cscli setup detect + acquis + install (no acquisition, no hub items)" {
    # no-op edge case, to make sure we don't crash
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  always:
	EOT

    rune -0 cscli setup detect
    assert_json '{setup:[{detected_service:"always"}]}'
    setup=$output
    rune -0 cscli setup datasources /dev/stdin <<<"$setup"
    rune -0 cscli setup install-hub /dev/stdin <<<"$setup"
}

@test "cscli setup detect (with collections)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
	    install:
	      collections:
	        - crowdsecurity/foobar
	  qox:
	    when:
	      - ProcessRunning("test-qox")
	    install:
	      collections:
	        - crowdsecurity/foobar
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
	    install:
	      collections:
	        - crowdsecurity/apache2
	EOT

    rune -0 cscli setup detect --force-process force-apache2,force-foobar
    rune -0 jq -Sc '.setup | sort' <(output)
    assert_json '[{install:{collections:["crowdsecurity/apache2"]},detected_service:"apache2"},{install:{collections:["crowdsecurity/foobar"]},detected_service:"foobar"}]'
}

@test "cscli setup detect (with acquisition)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
	    datasource:
	      source: file
	      labels:
	        type: foobar
	      filenames:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	EOT

    rune -0 cscli setup detect --force-process force-foobar
    rune -0 yq -op '.setup | sort_keys(..)' <(output)
    assert_output - <<-EOT
	0.datasource.filenames.0 = /var/log/apache2/*.log
	0.datasource.filenames.1 = /var/log/*http*/*.log
	0.datasource.labels.type = foobar
	0.datasource.source = file
	0.detected_service = foobar
	EOT

    rune -1 cscli setup detect --force-process mock-doesnotexist
    assert_stderr --partial "detecting services: process(es) forced but not supported: [mock-doesnotexist]"
}

@test "cscli setup detect (datasource validation)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	detect:
	  foobar:
	    datasource:
              labels:
                type: something
	EOT

    rune -1 cscli setup detect
    assert_stderr --partial "detecting services: invalid datasource for foobar: source is empty"

    # more datasource-specific tests are in detect_test.go
}

@test "cscli setup install-hub (dry run)" {
    # it's not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)

    # we install it
    rune -0 cscli setup install-hub /dev/stdin --dry-run <<< '{"setup":[{"install":{"collections":["crowdsecurity/apache2"]}}]}'
    assert_output 'dry-run: would install collection crowdsecurity/apache2'

    # still not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)

    # same with dependencies
    rune -0 cscli collections remove --all
    rune -0 cscli setup install-hub /dev/stdin --dry-run <<< '{"setup":[{"install":{"collections":["crowdsecurity/linux"]}}]}'
    assert_output 'dry-run: would install collection crowdsecurity/linux'
}

@test "cscli setup install-hub (dry run: install multiple collections)" {
    # it's not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)

    # we install it
    rune -0 cscli setup install-hub /dev/stdin --dry-run <<< '{"setup":[{"install":{"collections":["crowdsecurity/apache2"]}}]}'
    assert_output 'dry-run: would install collection crowdsecurity/apache2'

    # still not installed
    rune -0 cscli collections inspect crowdsecurity/apache2 -o json
    rune -0 jq -e '.installed == false' <(output)
}

@test "cscli setup install-hub (dry run: install multiple collections, parsers, scenarios, postoverflows)" {
    rune -0 cscli setup install-hub /dev/stdin --dry-run <<< '{"setup":[{"install":{"collections":["crowdsecurity/aws-console","crowdsecurity/caddy"],"parsers":["crowdsecurity/asterisk-logs"],"scenarios":["crowdsecurity/smb-fs"],"postoverflows":["crowdsecurity/cdn-whitelist","crowdsecurity/rdns"]}}]}'
    assert_line 'dry-run: would install collection crowdsecurity/aws-console'
    assert_line 'dry-run: would install collection crowdsecurity/caddy'
    assert_line 'dry-run: would install parser crowdsecurity/asterisk-logs'
    assert_line 'dry-run: would install scenario crowdsecurity/smb-fs'
    assert_line 'dry-run: would install postoverflow crowdsecurity/cdn-whitelist'
    assert_line 'dry-run: would install postoverflow crowdsecurity/rdns'

    rune -1 cscli setup install-hub /dev/stdin --dry-run <<< '{"setup":[{"install":{"collections":["crowdsecurity/foo"]}}]}'
    assert_stderr --partial 'collection crowdsecurity/foo not found'

}

@test "cscli setup datasources" {
    rune -0 cscli setup datasources --help
    assert_line --partial "--to-dir string   write the configuration to a directory, in multiple files"

    # single item

    rune -0 cscli setup datasources /dev/stdin <<-EOT
	setup:
	  - datasource:
	      source: file
	      labels:
	        type: syslog
	      filenames:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	EOT

    # remove diclaimer
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	source: file
	EOT

    # multiple items

    rune -0 cscli setup datasources /dev/stdin <<-EOT
	setup:
	  - datasource:
	      labels:
	        type: syslog
	      filenames:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	  - datasource:
	      labels:
	        type: foobar
	      filenames:
	        - /var/log/foobar/*.log
	  - datasource:
	      labels:
	        type: barbaz
	      filenames:
	        - /path/to/barbaz.log
	EOT

    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	---
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	---
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	EOT

    # multiple items, to a directory

    # avoid the BATS_TEST_TMPDIR variable, it can have a double //
    acquisdir=$(TMPDIR="$BATS_FILE_TMPDIR" mktemp -u)
    mkdir "$acquisdir"

    rune -0 cscli setup datasources /dev/stdin --to-dir "$acquisdir" <<-EOT
	setup:
	  - detected_service: apache2
	    datasource:
	      labels:
	        type: syslog
	      filenames:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	  - detected_service: foobar
	    datasource:
	      labels:
	        type: foobar
	      filenames:
	        - /var/log/foobar/*.log
	  - detected_service: barbaz
	    datasource:
	      labels:
	        type: barbaz
	      filenames:
	        - /path/to/barbaz.log
	EOT

    # XXX what if detected_service is missing?

    rune -0 cat "${acquisdir}/setup.apache2.yaml"
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	EOT

    rune -0 cat "${acquisdir}/setup.foobar.yaml"
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	EOT

    rune -0 cat "${acquisdir}/setup.barbaz.yaml"
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	EOT

    rm -rf -- "${acquisdir:?}"
    mkdir "$acquisdir"

    # having both filenames and journalctl does not generate two files: the datasource is copied as-is, even if incorrect

    rune -0 cscli setup datasources /dev/stdin --to-dir "$acquisdir" <<-EOT
	setup:
	  - detected_service: apache2
	    install:
	      collections:
	        - crowdsecurity/apache2
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

    rune -0 cat "${acquisdir}/setup.apache2.yaml"
    rune -0 yq '. head_comment=""' <(output)
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

    # the directory must exist
    rune -1 cscli setup datasources /dev/stdin --to-dir /path/does/not/exist <<< '{}'
    assert_stderr --partial "directory /path/does/not/exist does not exist"

    # of course it must be a directory

    touch "${acquisdir}/notadir"

    rune -1 cscli setup datasources /dev/stdin --to-dir "${acquisdir}/notadir" <<-EOT
	setup:
	  - detected_service: apache2
	    datasource:
	      filenames:
	        - /var/log/apache2/*.log
	EOT
    assert_stderr --partial "open ${acquisdir}/notadir/setup.apache2.yaml: not a directory"

    rm -rf -- "${acquisdir:?}"
}

@test "cscli setup datasources (disclaimer)" {
    disclaimer="This file was automatically generated"

    rune -0 cscli setup datasources /dev/stdin <<<"setup:"
    rune -0 yq 'head_comment' <(output)
    assert_output --partial "$disclaimer"

    rune -0 cscli setup datasources /dev/stdin <<-EOT
	setup:
          - detected_service: something
            datasource:
              labels:
                type: syslog
              filenames:
                - /var/log/something.log
	EOT
    rune -0 yq 'head_comment' <(output)
    assert_output --partial "$disclaimer"
}

@test "cscli setup (custom journalctl filter)" {
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	detect:
	  thewiz:
	    when:
	      - UnitFound("thewiz.service")
	    datasource:
	      source: journalctl
	      labels:
	        type: thewiz
	      journalctl_filter:
	        - "SYSLOG_IDENTIFIER=TheWiz"
	EOT

    rune -0 cscli setup detect --detect-config "$tempfile" --force-unit thewiz.service
    rune -0 jq -cS '.' <(output)
    assert_json '{setup:[{datasource:{source:"journalctl",journalctl_filter:["SYSLOG_IDENTIFIER=TheWiz"],labels:{type:"thewiz"}},detected_service:"thewiz"}]}'
    rune -0 cscli setup datasources <(output)
    rune -0 yq '. head_comment=""' <(output)
    assert_output - <<-EOT
	journalctl_filter:
	  - SYSLOG_IDENTIFIER=TheWiz
	labels:
	  type: thewiz
	source: journalctl
	EOT

    rm -f "$tempfile"
}

@test "cscli setup validate" {
    # an empty file is not enough
    rune -1 cscli setup validate /dev/null
    assert_output "EOF"
    assert_stderr --partial "invalid setup file"

    # this is ok; install nothing
    rune -0 cscli setup validate /dev/stdin <<-EOT
	setup:
	EOT
    refute_output

    rune -1 cscli setup validate /dev/stdin <<-EOT
	se tup:
	EOT
    assert_output - <<-EOT
	[1:1] unknown field "se tup"
	>  1 | se tup:
	       ^
	EOT
    assert_stderr --partial "invalid setup file"

    rune -1 cscli setup validate /dev/stdin <<-EOT
	setup:
	alsdk al; sdf
	EOT
    assert_output "while unmarshaling setup file: yaml: line 2: could not find expected ':'"
    assert_stderr --partial "invalid setup file"
}

