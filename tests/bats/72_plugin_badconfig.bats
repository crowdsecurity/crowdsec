#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"

    PLUGIN_DIR=$(config_yq '.config_paths.plugin_dir')
    # could have a trailing slash
    PLUGIN_DIR=$(realpath -s "${PLUGIN_DIR}")
    export PLUGIN_DIR

    PROFILES_PATH=$(config_yq '.api.server.profiles_path')
    export PROFILES_PATH
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
    rm -f "${PLUGIN_DIR}"/badname
    chmod go-w "${PLUGIN_DIR}"/notification-http
}

#----------

@test "${FILE} misconfigured plugin, only user is empty" {
    yq e '.plugin_config.user="" | .plugin_config.group="nogroup"' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: while getting process attributes: both plugin user and group must be set"
}

@test "${FILE} misconfigured plugin, only group is empty" {
    yq e '(.plugin_config.user="nobody") | (.plugin_config.group="")' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: while getting process attributes: both plugin user and group must be set"
}

@test "${FILE} misconfigured plugin, user does not exist" {
    yq e '(.plugin_config.user="userdoesnotexist") | (.plugin_config.group="groupdoesnotexist")' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: while getting process attributes: user: unknown user userdoesnotexist"
}

@test "${FILE} misconfigured plugin, group does not exist" {
    yq e '(.plugin_config.user=strenv(USER)) | (.plugin_config.group="groupdoesnotexist")' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: while getting process attributes: group: unknown group groupdoesnotexist"
}

@test "${FILE} bad plugin name" {
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    cp "${PLUGIN_DIR}"/notification-http "${PLUGIN_DIR}"/badname
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: plugin name ${PLUGIN_DIR}/badname is invalid. Name should be like {type-name}"
}

@test "${FILE} bad plugin permission (group writable)" {
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    chmod g+w "${PLUGIN_DIR}"/notification-http
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: plugin at ${PLUGIN_DIR}/notification-http is group writable, group writable plugins are invalid"
}

@test "${FILE} bad plugin permission (world writable)" {
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    chmod o+w "${PLUGIN_DIR}"/notification-http
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin: plugin at ${PLUGIN_DIR}/notification-http is world writable, world writable plugins are invalid"
}

@test "${FILE} config.yaml: missing .plugin_config section" {
    yq e 'del(.plugin_config)' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: plugins are enabled, but the plugin_config section is missing in the configuration"
}

@test "${FILE} config.yaml: missing config_paths.notification_dir" {
    yq e 'del(.config_paths.notification_dir)' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: plugins are enabled, but config_paths.notification_dir is not defined"
}

@test "${FILE} config.yaml: missing config_paths.plugin_dir" {
    yq e 'del(.config_paths.plugin_dir)' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: plugins are enabled, but config_paths.plugin_dir is not defined"
}

@test "${FILE} unable to run local API: while reading plugin config" {
    yq e '.config_paths.notification_dir="/this/path/does/not/exist"' -i "${CONFIG_YAML}"
    yq e '.notifications=["http_default"]' -i "${PROFILES_PATH}"
    run -1 --separate-stderr timeout 2s "${CROWDSEC}"
    run -0 echo "${stderr}"
    assert_output --partial "api server init: unable to run local API: while loading plugin config: open /this/path/does/not/exist: no such file or directory"
}
