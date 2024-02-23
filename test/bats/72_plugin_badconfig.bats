#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"

    PLUGIN_DIR=$(config_get '.config_paths.plugin_dir')
    # could have a trailing slash
    PLUGIN_DIR=$(realpath "${PLUGIN_DIR}")
    export PLUGIN_DIR

    PROFILES_PATH=$(config_get '.api.server.profiles_path')
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
    chmod go-w "${PLUGIN_DIR}"/notification-http || true
}

#----------

@test "misconfigured plugin, only user is empty" {
    config_set '.plugin_config.user="" | .plugin_config.group="nogroup"'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: while getting process attributes: both plugin user and group must be set" \
        "${CROWDSEC}"
}

@test "misconfigured plugin, only group is empty" {
    config_set '(.plugin_config.user="nobody") | (.plugin_config.group="")'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: while getting process attributes: both plugin user and group must be set" \
        "${CROWDSEC}"
}

@test "misconfigured plugin, user does not exist" {
    config_set '(.plugin_config.user="userdoesnotexist") | (.plugin_config.group="groupdoesnotexist")'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: while getting process attributes: user: unknown user userdoesnotexist" \
        "${CROWDSEC}"
}

@test "misconfigured plugin, group does not exist" {
    config_set '(.plugin_config.user=strenv(USER)) | (.plugin_config.group="groupdoesnotexist")'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: while getting process attributes: group: unknown group groupdoesnotexist" \
        "${CROWDSEC}"
}

@test "bad plugin name" {
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    cp "${PLUGIN_DIR}"/notification-http "${PLUGIN_DIR}"/badname
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: plugin name ${PLUGIN_DIR}/badname is invalid. Name should be like {type-name}" \
        "${CROWDSEC}"
}

@test "duplicate notification config" {
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    # email_default has two configurations
    rune -0 yq -i '.name="email_default"' "$CONFIG_DIR/notifications/http.yaml"
    # enable a notification, otherwise plugins are ignored
    config_set "${PROFILES_PATH}" '.notifications=["slack_default"]'
    # the slack plugin may fail or not, but we just need the logs
    config_set '.common.log_media="stdout"'
    rune wait-for \
        --err "notification 'email_default' is defined multiple times" \
        "${CROWDSEC}"
}

@test "bad plugin permission (group writable)" {
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    chmod g+w "${PLUGIN_DIR}"/notification-http
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: plugin at ${PLUGIN_DIR}/notification-http is group writable, group writable plugins are invalid" \
        "${CROWDSEC}"
}

@test "bad plugin permission (world writable)" {
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    chmod o+w "${PLUGIN_DIR}"/notification-http
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin: plugin at ${PLUGIN_DIR}/notification-http is world writable, world writable plugins are invalid" \
        "${CROWDSEC}"
}

@test "config.yaml: missing .plugin_config section" {
    config_set 'del(.plugin_config)'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: plugins are enabled, but the plugin_config section is missing in the configuration" \
        "${CROWDSEC}"
}

@test "config.yaml: missing config_paths.notification_dir" {
    config_set 'del(.config_paths.notification_dir)'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: plugins are enabled, but config_paths.notification_dir is not defined" \
        "${CROWDSEC}"
}

@test "config.yaml: missing config_paths.plugin_dir" {
    config_set 'del(.config_paths.plugin_dir)'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: plugins are enabled, but config_paths.plugin_dir is not defined" \
        "${CROWDSEC}"
}

@test "unable to run plugin broker: while reading plugin config" {
    config_set '.config_paths.notification_dir="/this/path/does/not/exist"'
    config_set "${PROFILES_PATH}" '.notifications=["http_default"]'
    rune -0 wait-for \
        --err "api server init: unable to run plugin broker: while loading plugin config: open /this/path/does/not/exist: no such file or directory" \
        "${CROWDSEC}"
}
