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
    # don't run crowdsec here, not all tests require a running instance
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
    # error is displayed with print, not as a log entry
    assert_stderr --partial 'unknown command "blahblah" for "cscli"'
    refute_stderr --partial 'level=fatal'
}

@test "cscli version" {
    rune -0 cscli version
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
    rm "$CONFIG_YAML"
    rune -0 cscli version
    assert_output --partial "version:"
}

@test "cscli help" {
    rune -0 cscli help
    assert_line "Available Commands:"
    assert_line --regexp ".* help .* Help about any command"

    # should work without configuration file
    rm "$CONFIG_YAML"
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

    sock=$(config_get '.api.server.listen_socket')

    rune -0 cscli config show -o human
    assert_line --regexp ".*- URL +: http://127.0.0.1:8080/"
    assert_line --regexp ".*- Login +: githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?"
    assert_line --regexp ".*- Credentials File +: .*/local_api_credentials.yaml"
    assert_line --regexp ".*- Listen URL +: 127.0.0.1:8080"
    assert_line --regexp ".*- Listen Socket +: $sock"

    rune -0 cscli config show -o json
    rune -0 jq -c '.API.Client.Credentials | [.url,.login[0:32]]' <(output)
    assert_json '["http://127.0.0.1:8080/","githubciXXXXXXXXXXXXXXXXXXXXXXXX"]'

    # pointer to boolean

    rune -0 cscli config show --key Config.API.Client.InsecureSkipVerify
    assert_output "&false"

    # complex type
    rune -0 cscli config show --key Config.Prometheus
    assert_output - <<-EOT
	&csconfig.PrometheusCfg{
	  Enabled: true,
	  Level: "full",
	  ListenAddr: "127.0.0.1",
	  ListenPort: 6060,
	}
	EOT
}

@test "cscli - required configuration paths" {
    config=$(cat "$CONFIG_YAML")
    configdir=$(config_get '.config_paths.config_dir')

    # required configuration paths with no defaults

    config_set 'del(.config_paths)'
    rune -1 cscli hub list
    assert_stderr --partial 'no configuration paths provided'
    echo "$config" > "$CONFIG_YAML"

    config_set 'del(.config_paths.data_dir)'
    rune -1 cscli hub list
    assert_stderr --partial "please provide a data directory with the 'data_dir' directive in the 'config_paths' section"
    echo "$config" > "$CONFIG_YAML"

    # defaults

    config_set 'del(.config_paths.hub_dir)'
    rune -0 cscli hub list
    rune -0 cscli config show --key Config.ConfigPaths.HubDir
    assert_output "$configdir/hub"
    echo "$config" > "$CONFIG_YAML"

    config_set 'del(.config_paths.index_path)'
    rune -0 cscli hub list
    rune -0 cscli config show --key Config.ConfigPaths.HubIndexFile
    assert_output "$configdir/hub/.index.json"
    echo "$config" > "$CONFIG_YAML"
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
    CONFIG_DIR=$(config_get '.config_paths.config_dir')

    rune -1 cscli config backup "/dev/null/blah"
    assert_stderr --partial "'cscli config backup' has been removed, you can manually backup/restore $CONFIG_DIR instead"

    rune -1 cscli config restore "/dev/null/blah"
    assert_stderr --partial "'cscli config restore' has been removed, you can manually backup/restore $CONFIG_DIR instead"
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

    rm "$CONFIG_YAML"
    rune -0 cscli completion bash
    assert_output --partial "# bash completion for cscli"
}

@test "cscli support dump (smoke test)" {
    rune -0 cscli support dump -f "$BATS_TEST_TMPDIR"/dump.zip
    assert_file_exists "$BATS_TEST_TMPDIR"/dump.zip
}

@test "cscli explain" {
    rune -0 ./instance-crowdsec start
    line="Sep 19 18:33:22 scw-d95986 sshd[24347]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4"

    rune -0 cscli parsers install crowdsecurity/syslog-logs
    rune -0 cscli collections install crowdsecurity/sshd

    rune -0 cscli explain --log "$line" --type syslog --only-successful-parsers --crowdsec "$CROWDSEC"
    assert_output - <"$BATS_TEST_DIRNAME"/testdata/explain/explain-log.txt

    rune -0 cscli parsers remove --all --purge
    rune -1 cscli explain --log "$line" --type syslog --crowdsec "$CROWDSEC"
    assert_stderr --partial "unable to load parser dump result: no parser found. Please install the appropriate parser and retry"
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
    cd "$BATS_TEST_TMPDIR"
    rune -1 cscli doc
    refute_output
    assert_stderr --regexp 'failed to generate cscli documentation: open doc/.*: no such file or directory'

    mkdir -p doc
    rune -0 cscli doc
    assert_output "Documentation generated in ./doc"
    refute_stderr
    assert_file_exists "doc/cscli.md"
    assert_file_not_exist "doc/cscli_setup.md"

    # commands guarded by feature flags are not documented unless the feature flag is set

    export CROWDSEC_FEATURE_CSCLI_SETUP="true"
    rune -0 cscli doc
    assert_file_exists "doc/cscli_setup.md"

    # specify a target directory
    mkdir -p "$BATS_TEST_TMPDIR/doc2"
    rune -0 cscli doc --target "$BATS_TEST_TMPDIR/doc2"
    assert_output "Documentation generated in $BATS_TEST_TMPDIR/doc2"
    refute_stderr
    assert_file_exists "$BATS_TEST_TMPDIR/doc2/cscli_setup.md"

}

@test "feature.yaml for subcommands" {
    # it is possible to enable subcommands with feature flags defined in feature.yaml

    rune -1 cscli setup
    assert_stderr --partial 'unknown command "setup" for "cscli"'
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    echo ' - cscli_setup' >> "$CONFIG_DIR"/feature.yaml
    rune -0 cscli setup
    assert_output --partial 'cscli setup [command]'
}

@test "cscli config feature-flags" {
    # disabled
    rune -0 cscli config feature-flags
    assert_line '✗ cscli_setup: Enable cscli setup command (service detection)'

    # enabled in feature.yaml
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    echo ' - cscli_setup' >> "$CONFIG_DIR"/feature.yaml
    rune -0 cscli config feature-flags
    assert_line '✓ cscli_setup: Enable cscli setup command (service detection)'

    # enabled in environment
    # shellcheck disable=SC2031
    export CROWDSEC_FEATURE_CSCLI_SETUP="true"
    rune -0 cscli config feature-flags
    assert_line '✓ cscli_setup: Enable cscli setup command (service detection)'

    # there are no retired features
    rune -0 cscli config feature-flags --retired
}
