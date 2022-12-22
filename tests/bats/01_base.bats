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
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

# to silence shellcheck
declare stderr

#----------

@test "cscli - usage" {
    run -0 cscli
    assert_output --partial "Usage:"
    assert_output --partial "cscli [command]"
    assert_output --partial "Available Commands:"

    # no "usage" output after every error
    run -1 --separate-stderr cscli blahblah
    # error is displayed as log entry, not with print
    assert_stderr --partial 'level=fatal msg="unknown command \"blahblah\" for \"cscli\""'
    refute_stderr --partial 'unknown command "blahblah" for "cscli"'
}

@test "cscli version" {
    run -0 cscli version
    assert_output --partial "version:"
    assert_output --partial "Codename:"
    assert_output --partial "BuildDate:"
    assert_output --partial "GoVersion:"
    assert_output --partial "Platform:"
    assert_output --partial "Constraint_parser:"
    assert_output --partial "Constraint_scenario:"
    assert_output --partial "Constraint_api:"
    assert_output --partial "Constraint_acquis:"

    # should work without configuration file
    rm "${CONFIG_YAML}"
    run -0 cscli version
    assert_output --partial "version:"
}

@test "cscli help" {
    run -0 cscli help
    assert_line "Available Commands:"
    assert_line --regexp ".* help .* Help about any command"

    # should work without configuration file
    rm "${CONFIG_YAML}"
    run -0 cscli help
    assert_line "Available Commands:"
}

@test "cscli config show -o human" {
    run -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"
}

@test "cscli config show -o json" {
    run -0 cscli config show -o json
    assert_output --partial '"API":'
    assert_output --partial '"Common":'
    assert_output --partial '"ConfigPaths":'
    assert_output --partial '"Crowdsec":'
    assert_output --partial '"Cscli":'
    assert_output --partial '"DbConfig":'
    assert_output --partial '"Hub":'
    assert_output --partial '"PluginConfig":'
    assert_output --partial '"Prometheus":'
}

@test "cscli config show -o raw" {
    run -0 cscli config show -o raw
    assert_line "api:"
    assert_line "common:"
    assert_line "config_paths:"
    assert_line "crowdsec_service:"
    assert_line "cscli:"
    assert_line "db_config:"
    assert_line "plugin_config:"
    assert_line "prometheus:"
}

@test "cscli config show --key" {
    run -0 cscli config show --key Config.API.Server.ListenURI
    assert_output "127.0.0.1:8080"
}

@test "cscli config backup / restore" {
    # test that we need a valid path
    # disabled because in CI, the empty string is not passed as a parameter
    #run -1 --separate-stderr cscli config backup ""
    #assert_stderr --partial "failed to backup config: directory path can't be empty"

    run -1 --separate-stderr cscli config backup "/dev/null/blah"
    assert_stderr --partial "failed to backup config: while creating /dev/null/blah: mkdir /dev/null/blah: not a directory"

    # pick a dirpath
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)

    # succeed the first time
    run -0 cscli config backup "${backupdir}"
    assert_output --partial "Starting configuration backup"

    # don't overwrite an existing backup
    run -1 --separate-stderr cscli config backup "${backupdir}"
    assert_stderr --partial "failed to backup config"
    assert_stderr --partial "file exists"

    SIMULATION_YAML="$(config_get '.config_paths.simulation_path')"

    # restore
    rm "${SIMULATION_YAML}"
    run -0 cscli config restore "${backupdir}"
    assert_file_exist "${SIMULATION_YAML}"

    # cleanup
    rm -rf -- "${backupdir:?}"

    # backup: detect missing files
    rm "${SIMULATION_YAML}"
    run -1 --separate-stderr cscli config backup "${backupdir}"
    assert_stderr --regexp "failed to backup config: failed copy .* to .*: stat .*: no such file or directory"
    rm -rf -- "${backupdir:?}"
}

@test "cscli lapi status" {
    run -0 --separate-stderr cscli lapi status

    run -0 echo "${stderr}"
    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial " on http://127.0.0.1:8080/"
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli - missing LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    rm -f "${LOCAL_API_CREDENTIALS}"
    run -1 --separate-stderr cscli lapi status
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"

    run -1 --separate-stderr cscli alerts list
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"

    run -1 --separate-stderr cscli decisions list
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"
}

@test "cscli - empty LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    truncate -s 0 "${LOCAL_API_CREDENTIALS}"
    run -1 --separate-stderr cscli lapi status
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"

    run -1 --separate-stderr cscli alerts list
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"

    run -1 --separate-stderr cscli decisions list
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"
}

@test "cscli - missing LAPI client settings" {
    config_set 'del(.api.client)'
    run -1 --separate-stderr cscli lapi status
    assert_stderr --partial "loading api client: no API client section in configuration"

    run -1 --separate-stderr cscli alerts list
    assert_stderr --partial "loading api client: no API client section in configuration"

    run -1 --separate-stderr cscli decisions list
    assert_stderr --partial "loading api client: no API client section in configuration"
}

@test "cscli - malformed LAPI url" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "${LOCAL_API_CREDENTIALS}" '.url="https://127.0.0.1:-80"'

    run -1 --separate-stderr cscli lapi status
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'

    run -1 --separate-stderr cscli alerts list
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'

    run -1 --separate-stderr cscli decisions list
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'
}

@test "cscli metrics" {
    run -0 cscli lapi status
    run -0 --separate-stderr cscli metrics
    assert_output --partial "Route"
    assert_output --partial '/v1/watchers/login'
    assert_output --partial "Local Api Metrics:"

}

@test "'cscli completion' with or without configuration file" {
    run -0 cscli completion bash
    assert_output --partial "# bash completion for cscli"
    run -0 cscli completion zsh
    assert_output --partial "# zsh completion for cscli"
    run -0 cscli completion powershell
    assert_output --partial "# powershell completion for cscli"
    run -0 cscli completion fish
    assert_output --partial "# fish completion for cscli"

    rm "${CONFIG_YAML}"
    run -0 cscli completion bash
    assert_output --partial "# bash completion for cscli"
}

@test "cscli hub list" {
    # we check for the presence of some objects. There may be others when we
    # use $PACKAGE_TESTING, so the order is not important.

    run -0 cscli hub list -o human
    assert_line --regexp '^ crowdsecurity/linux'
    assert_line --regexp '^ crowdsecurity/sshd'
    assert_line --regexp '^ crowdsecurity/dateparse-enrich'
    assert_line --regexp '^ crowdsecurity/geoip-enrich'
    assert_line --regexp '^ crowdsecurity/sshd-logs'
    assert_line --regexp '^ crowdsecurity/syslog-logs'
    assert_line --regexp '^ crowdsecurity/ssh-bf'
    assert_line --regexp '^ crowdsecurity/ssh-slow-bf'

    run -0 cscli hub list -o raw
    assert_line --regexp '^crowdsecurity/linux,enabled,[0-9]+\.[0-9]+,core linux support : syslog\+geoip\+ssh,collections$'
    assert_line --regexp '^crowdsecurity/sshd,enabled,[0-9]+\.[0-9]+,sshd support : parser and brute-force detection,collections$'
    assert_line --regexp '^crowdsecurity/dateparse-enrich,enabled,[0-9]+\.[0-9]+,,parsers$'
    assert_line --regexp '^crowdsecurity/geoip-enrich,enabled,[0-9]+\.[0-9]+,"Populate event with geoloc info : as, country, coords, source range.",parsers$'
    assert_line --regexp '^crowdsecurity/sshd-logs,enabled,[0-9]+\.[0-9]+,Parse openSSH logs,parsers$'
    assert_line --regexp '^crowdsecurity/syslog-logs,enabled,[0-9]+\.[0-9]+,,parsers$'
    assert_line --regexp '^crowdsecurity/ssh-bf,enabled,[0-9]+\.[0-9]+,Detect ssh bruteforce,scenarios$'
    assert_line --regexp '^crowdsecurity/ssh-slow-bf,enabled,[0-9]+\.[0-9]+,Detect slow ssh bruteforce,scenarios$'

    run -0 cscli hub list -o json
    run jq -r '.collections[].name, .parsers[].name, .scenarios[].name' <(output)
    assert_line 'crowdsecurity/linux'
    assert_line 'crowdsecurity/sshd'
    assert_line 'crowdsecurity/dateparse-enrich'
    assert_line 'crowdsecurity/geoip-enrich'
    assert_line 'crowdsecurity/sshd-logs'
    assert_line 'crowdsecurity/syslog-logs'
    assert_line 'crowdsecurity/ssh-bf'
    assert_line 'crowdsecurity/ssh-slow-bf'
}

@test "cscli support dump (smoke test)" {
    run -0 cscli support dump -f "$BATS_TEST_TMPDIR"/dump.zip
    assert_file_exist "$BATS_TEST_TMPDIR"/dump.zip
}
