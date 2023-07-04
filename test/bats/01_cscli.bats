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
    cd "$TEST_DIR" || exit 1
    ./instance-crowdsec stop
}

#----------

@test "cscli - usage" {
    rune -0 cscli
    assert_output --partial "Usage:"
    assert_output --partial "cscli [command]"
    assert_output --partial "Available Commands:"

    # no "usage" output after every error
    rune -1 cscli blahblah
    # error is displayed as log entry, not with print
    assert_stderr --partial 'level=fatal msg="unknown command \"blahblah\" for \"cscli\""'
    refute_stderr --partial 'unknown command "blahblah" for "cscli"'
}

@test "cscli version" {
    rune -0 cscli version
    assert_stderr --partial "version:"
    assert_stderr --partial "Codename:"
    assert_stderr --partial "BuildDate:"
    assert_stderr --partial "GoVersion:"
    assert_stderr --partial "Platform:"
    assert_stderr --partial "Constraint_parser:"
    assert_stderr --partial "Constraint_scenario:"
    assert_stderr --partial "Constraint_api:"
    assert_stderr --partial "Constraint_acquis:"

    # should work without configuration file
    rm "${CONFIG_YAML}"
    rune -0 cscli version
    assert_stderr --partial "version:"
}

@test "cscli help" {
    rune -0 cscli help
    assert_line "Available Commands:"
    assert_line --regexp ".* help .* Help about any command"

    # should work without configuration file
    rm "${CONFIG_YAML}"
    rune -0 cscli help
    assert_line "Available Commands:"
}

@test "cscli config show" {
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"

    rune -0 cscli config show -o json
    assert_output --partial '"API":'
    assert_output --partial '"Common":'
    assert_output --partial '"ConfigPaths":'
    assert_output --partial '"Crowdsec":'
    assert_output --partial '"Cscli":'
    assert_output --partial '"DbConfig":'
    assert_output --partial '"Hub":'
    assert_output --partial '"PluginConfig":'
    assert_output --partial '"Prometheus":'

    rune -0 cscli config show -o raw
    assert_line "api:"
    assert_line "common:"
    assert_line "config_paths:"
    assert_line "crowdsec_service:"
    assert_line "cscli:"
    assert_line "db_config:"
    assert_line "plugin_config:"
    assert_line "prometheus:"

    rune -0 cscli config show --key Config.API.Server.ListenURI
    assert_output "127.0.0.1:8080"

    # check that LAPI configuration is loaded (human and json, not shows in raw)

    rune -0 cscli config show -o human
    assert_line --regexp ".*- URL\s+: http://127.0.0.1:8080/"
    assert_line --regexp ".*- Login\s+: githubciXXXXXXXXXXXXXXXXXXXXXXXX"
    assert_line --regexp ".*- Credentials File\s+: .*/local_api_credentials.yaml"

    rune -0 cscli config show -o json
    rune -0 jq -c '.API.Client.Credentials | [.url,.login]' <(output)
    assert_output '["http://127.0.0.1:8080/","githubciXXXXXXXXXXXXXXXXXXXXXXXX"]'
}

@test "cscli config show-yaml" {
    rune -0 cscli config show-yaml
    rune -0 yq .common.log_level <(output)
    assert_output "info"
    echo 'common: {"log_level": "debug"}' >> "${CONFIG_YAML}.local"
    rune -0 cscli config show-yaml
    rune -0 yq .common.log_level <(output)
    assert_output "debug"
}

@test "cscli config backup / restore" {
    # test that we need a valid path
    # disabled because in CI, the empty string is not passed as a parameter
    #rune -1 cscli config backup ""
    #assert_stderr --partial "failed to backup config: directory path can't be empty"

    rune -1 cscli config backup "/dev/null/blah"
    assert_stderr --partial "failed to backup config: while creating /dev/null/blah: mkdir /dev/null/blah: not a directory"

    # pick a dirpath
    backupdir=$(TMPDIR="${BATS_TEST_TMPDIR}" mktemp -u)

    # succeed the first time
    rune -0 cscli config backup "${backupdir}"
    assert_stderr --partial "Starting configuration backup"

    # don't overwrite an existing backup
    rune -1 cscli config backup "${backupdir}"
    assert_stderr --partial "failed to backup config"
    assert_stderr --partial "file exists"

    SIMULATION_YAML="$(config_get '.config_paths.simulation_path')"

    # restore
    rm "${SIMULATION_YAML}"
    rune -0 cscli config restore "${backupdir}"
    assert_file_exist "${SIMULATION_YAML}"

    # cleanup
    rm -rf -- "${backupdir:?}"

    # backup: detect missing files
    rm "${SIMULATION_YAML}"
    rune -1 cscli config backup "${backupdir}"
    assert_stderr --regexp "failed to backup config: failed copy .* to .*: stat .*: no such file or directory"
    rm -rf -- "${backupdir:?}"
}

@test "cscli lapi status" {
    rune -0 cscli lapi status

    assert_stderr --partial "Loaded credentials from"
    assert_stderr --partial "Trying to authenticate with username"
    assert_stderr --partial " on http://127.0.0.1:8080/"
    assert_stderr --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli - missing LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    rm -f "${LOCAL_API_CREDENTIALS}"
    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"

    rune -1 cscli alerts list
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"

    rune -1 cscli decisions list
    assert_stderr --partial "loading api client: while reading yaml file: open ${LOCAL_API_CREDENTIALS}: no such file or directory"
}

@test "cscli - empty LAPI credentials file" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    truncate -s 0 "${LOCAL_API_CREDENTIALS}"
    rune -1 cscli lapi status
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"

    rune -1 cscli alerts list
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"

    rune -1 cscli decisions list
    assert_stderr --partial "no credentials or URL found in api client configuration '${LOCAL_API_CREDENTIALS}'"
}

@test "cscli - missing LAPI client settings" {
    config_set 'del(.api.client)'
    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: no API client section in configuration"

    rune -1 cscli alerts list
    assert_stderr --partial "loading api client: no API client section in configuration"

    rune -1 cscli decisions list
    assert_stderr --partial "loading api client: no API client section in configuration"
}

@test "cscli - malformed LAPI url" {
    LOCAL_API_CREDENTIALS=$(config_get '.api.client.credentials_path')
    config_set "${LOCAL_API_CREDENTIALS}" '.url="https://127.0.0.1:-80"'

    rune -1 cscli lapi status
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'

    rune -1 cscli alerts list
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'

    rune -1 cscli decisions list
    assert_stderr --partial 'parsing api url'
    assert_stderr --partial 'invalid port \":-80\" after host'
}

@test "cscli metrics" {
    rune -0 cscli lapi status
    rune -0 cscli metrics
    assert_output --partial "Route"
    assert_output --partial '/v1/watchers/login'
    assert_output --partial "Local Api Metrics:"
}

@test "'cscli completion' with or without configuration file" {
    rune -0 cscli completion bash
    assert_output --partial "# bash completion for cscli"
    rune -0 cscli completion zsh
    assert_output --partial "# zsh completion for cscli"
    rune -0 cscli completion powershell
    assert_output --partial "# powershell completion for cscli"
    rune -0 cscli completion fish
    assert_output --partial "# fish completion for cscli"

    rm "${CONFIG_YAML}"
    rune -0 cscli completion bash
    assert_output --partial "# bash completion for cscli"
}

@test "cscli hub list" {
    # we check for the presence of some objects. There may be others when we
    # use $PACKAGE_TESTING, so the order is not important.

    rune -0 cscli hub list -o human
    assert_line --regexp '^ crowdsecurity/linux'
    assert_line --regexp '^ crowdsecurity/sshd'
    assert_line --regexp '^ crowdsecurity/dateparse-enrich'
    assert_line --regexp '^ crowdsecurity/geoip-enrich'
    assert_line --regexp '^ crowdsecurity/sshd-logs'
    assert_line --regexp '^ crowdsecurity/syslog-logs'
    assert_line --regexp '^ crowdsecurity/ssh-bf'
    assert_line --regexp '^ crowdsecurity/ssh-slow-bf'

    rune -0 cscli hub list -o raw
    assert_line --regexp '^crowdsecurity/linux,enabled,[0-9]+\.[0-9]+,core linux support : syslog\+geoip\+ssh,collections$'
    assert_line --regexp '^crowdsecurity/sshd,enabled,[0-9]+\.[0-9]+,sshd support : parser and brute-force detection,collections$'
    assert_line --regexp '^crowdsecurity/dateparse-enrich,enabled,[0-9]+\.[0-9]+,,parsers$'
    assert_line --regexp '^crowdsecurity/geoip-enrich,enabled,[0-9]+\.[0-9]+,"Populate event with geoloc info : as, country, coords, source range.",parsers$'
    assert_line --regexp '^crowdsecurity/sshd-logs,enabled,[0-9]+\.[0-9]+,Parse openSSH logs,parsers$'
    assert_line --regexp '^crowdsecurity/syslog-logs,enabled,[0-9]+\.[0-9]+,,parsers$'
    assert_line --regexp '^crowdsecurity/ssh-bf,enabled,[0-9]+\.[0-9]+,Detect ssh bruteforce,scenarios$'
    assert_line --regexp '^crowdsecurity/ssh-slow-bf,enabled,[0-9]+\.[0-9]+,Detect slow ssh bruteforce,scenarios$'

    rune -0 cscli hub list -o json
    rune -0 jq -r '.collections[].name, .parsers[].name, .scenarios[].name' <(output)
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
    rune -0 cscli support dump -f "$BATS_TEST_TMPDIR"/dump.zip
    assert_file_exist "$BATS_TEST_TMPDIR"/dump.zip
}

@test "cscli explain" {
    rune -0 cscli explain --log "Sep 19 18:33:22 scw-d95986 sshd[24347]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4" --type syslog --crowdsec "$CROWDSEC"
    assert_output - <"$BATS_TEST_DIRNAME"/testdata/explain/explain-log.txt
}

@test 'Allow variable expansion and literal $ characters in passwords' {
    export DB_PASSWORD='P@ssw0rd'
    # shellcheck disable=SC2016
    config_set '.db_config.password="$DB_PASSWORD"'
    rune -0 cscli config show --key Config.DbConfig.Password
    assert_output 'P@ssw0rd'

    # shellcheck disable=SC2016
    config_set '.db_config.password="$3cureP@ssw0rd"'
    rune -0 cscli config show --key Config.DbConfig.Password
    # shellcheck disable=SC2016
    assert_output '$3cureP@ssw0rd'

    config_set '.db_config.password="P@ssw0rd$"'
    rune -0 cscli config show --key Config.DbConfig.Password
    assert_output 'P@ssw0rd$'
}

@test "cscli doc" {
    # generating documentation requires a directory named "doc"

    cd "$BATS_TEST_TMPDIR"
    rune -1 cscli doc
    refute_output
    assert_stderr --regexp 'Failed to generate cobra doc: open doc/.*: no such file or directory'

    mkdir -p doc
    rune -0 cscli doc
    refute_output
    refute_stderr
    assert_file_exist "doc/cscli.md"
    assert_file_not_exist "doc/cscli_setup.md"

    # commands guarded by feature flags are not documented unless the feature flag is set

    export CROWDSEC_FEATURE_CSCLI_SETUP="true"
    rune -0 cscli doc
    assert_file_exist "doc/cscli_setup.md"
}

@test "feature.yaml for subcommands" {
    # it is possible to enable subcommands with feature flags defined in feature.yaml

    rune -1 cscli setup
    assert_stderr --partial 'unknown command \"setup\" for \"cscli\"'
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    echo ' - cscli_setup' >> "$CONFIG_DIR"/feature.yaml
    rune -0 cscli setup
    assert_output --partial 'cscli setup [command]'
}
