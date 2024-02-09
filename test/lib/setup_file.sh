#!/usr/bin/env bash

# this should have effect globally, for all tests
# https://github.com/bats-core/bats-core/blob/master/docs/source/warnings/BW02.rst
bats_require_minimum_version 1.5.0

debug() {
    echo 'exec 1<&-; exec 2<&-; exec 1>&3; exec 2>&1'
}
export -f debug

# redirects stdout and stderr to &3 otherwise the errors in setup, teardown would
# go unreported.
# BUT - don't do this in test functions. Everything written to stdout and
# stderr after this line will go to the terminal, but in the tests, these
# are supposed to be collected and shown only in case of test failure
# (see options --print-output-on-failure and --show-output-of-passing-tests)
eval "$(debug)"

# Allow tests to use relative paths for helper scripts.
# shellcheck disable=SC2164
cd "${TEST_DIR}"
export PATH="${TEST_DIR}/bin:${PATH}"

# complain if there's a crowdsec running system-wide or leftover from a previous test
./bin/assert-crowdsec-not-running

# we can prepend the filename to the test descriptions (useful to feed a TAP consumer)
if [[ "${PREFIX_TEST_NAMES_WITH_FILE:-false}" == "true" ]]; then
  BATS_TEST_NAME_PREFIX="$(basename "${BATS_TEST_FILENAME}" .bats): "
  export BATS_TEST_NAME_PREFIX
fi

# before bats 1.7, we did that by hand
FILE=
export FILE

# the variables exported here can be seen in other setup/teardown/test functions
# MYVAR=something
# export MYVAR

# functions too
cscli() {
    "${CSCLI}" "$@"
}
export -f cscli

config_get() {
    local cfg="${CONFIG_YAML}"
    if [[ $# -ge 2 ]]; then
        cfg="$1"
        shift
    fi

    yq e "$1" "${cfg}"
}
export -f config_get

config_set() {
    local cfg="${CONFIG_YAML}"
    if [[ $# -ge 2 ]]; then
        cfg="$1"
        shift
    fi

    yq e "$1" -i "${cfg}"
}
export -f config_set

config_disable_agent() {
    config_set '.crowdsec_service.enable=false'
    # this should be equivalent to:
    # config_set 'del(.crowdsec_service)'
}
export -f config_disable_agent

config_log_stderr() {
    config_set '.common.log_media="stdout"'
}
export -f config_log_stderr

config_disable_lapi() {
    config_set '.api.server.enable=false'
    # this should be equivalent to:
    # config_set 'del(.api.server)'
}
export -f config_disable_lapi

config_disable_capi() {
    config_set 'del(.api.server.online_client)'
}
export -f config_disable_capi

config_enable_capi() {
    online_api_credentials="$(dirname "${CONFIG_YAML}")/online_api_credentials.yaml" \
        config_set '.api.server.online_client.credentials_path=strenv(online_api_credentials)'
}
export -f config_enable_capi

# We use these functions like this:
#    somecommand <(stderr)
# to provide a standard input to "somecommand".
# The alternatives echo "$stderr" or <<<"$stderr"
# ("here string" in bash jargon)
# are worse because they add a newline,
# even if the variable is empty.

# shellcheck disable=SC2154
stderr() {
    printf '%s' "${stderr}"
}
export -f stderr

# shellcheck disable=SC2154
output() {
    printf '%s' "${output}"
}
export -f output

is_package_testing() {
    [[ "$PACKAGE_TESTING" != "" ]]
}
export -f is_package_testing

is_db_postgres() {
    [[ "$DB_BACKEND" =~ ^postgres|pgx$ ]]
}
export -f is_db_postgres

is_db_mysql() {
    [[ "$DB_BACKEND" == "mysql" ]]
}
export -f is_db_mysql

is_db_sqlite() {
    [[ "$DB_BACKEND" == "sqlite" ]]
}
export -f is_db_sqlite

crowdsec_log() {
    echo "$(config_get .common.log_dir)"/crowdsec.log
}
export -f crowdsec_log

truncate_log() {
    true > "$(crowdsec_log)"
}
export -f truncate_log

assert_log() {
    local oldout="${output:-}"
    output="$(cat "$(crowdsec_log)")"
    assert_output "$@"
    output="${oldout}"
}
export -f assert_log

# Compare ignoring the key order, and allow "expected" without quoted identifiers.
# Preserve the output variable in case the following commands require it.
assert_json() {
    local oldout="${output}"
    # validate actual, sort
    run -0 jq -Sen "${output}"
    local actual="${output}"

    # handle stdin, quote identifiers, sort
    local expected="$1"
    if [[ "${expected}" == "-" ]]; then
        expected="$(cat)"
    fi
    run -0 jq -Sn "${expected}"
    expected="${output}"

    #shellcheck disable=SC2016
    run jq -ne --argjson a "${actual}" --argjson b "${expected}" '$a == $b'
    #shellcheck disable=SC2154
    if [[ "${status}" -ne 0 ]]; then
        echo "expect: $(jq -c <<<"${expected}")"
        echo "actual: $(jq -c <<<"${actual}")"
        diff <(echo "${actual}") <(echo "${expected}")
        fail "json does not match"
    fi
    output="${oldout}"
}
export -f assert_json

# Check if there's something on stdin by consuming it. Only use this as a way
# to check if something was passed by mistake, since if you read it, it will be
# incomplete.
is_stdin_empty() {
    if read -r -t 0.1; then
        return 1
    fi
    return 0
}
export -f is_stdin_empty

assert_stderr() {
    # it is never useful to call this without arguments
    if [[ "$#" -eq 0 ]]; then
        # maybe the caller forgot to use '-' with an heredoc
        if ! is_stdin_empty; then
            fail "${FUNCNAME[0]}: called with stdin and no arguments (heredoc?)"
        fi
        fail "${FUNCNAME[0]}: called with no arguments"
    fi

    local oldout="${output}"
    run -0 echo "${stderr}"
    assert_output "$@"
    output="${oldout}"
}
export -f assert_stderr

# like refute_output, but for stderr
refute_stderr() {
    # calling this without arguments is ok, as long as stdin in empty
    if ! is_stdin_empty; then
        fail "${FUNCNAME[0]}: called with stdin (heredoc?)"
    fi

    local oldout="${output}"
    run -0 echo "${stderr}"
    refute_output "$@"
    output="${oldout}"
}
export -f refute_stderr

# like assert_output, but for stderr
assert_stderr_line() {
    if [[ "$#" -eq 0 ]]; then
        fail "${FUNCNAME[0]}: called with no arguments"
    fi

    local oldout="${output}"
    run -0 echo "${stderr}"
    assert_line "$@"
    output="${oldout}"
}
export -f assert_stderr_line

# remove all installed items and data
hub_purge_all() {
    local CONFIG_DIR
    local itemtype
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    for itemtype in $(cscli hub types -o raw); do
        rm -rf "$CONFIG_DIR"/"${itemtype:?}"/* "$CONFIG_DIR"/hub/"${itemtype:?}"/*
    done
    local DATA_DIR
    DATA_DIR=$(config_get .config_paths.data_dir)
    # should remove everything except the db (find $DATA_DIR -not -name "crowdsec.db*" -delete),
    # but don't play with fire if there is a misconfiguration
    rm -rfv "$DATA_DIR"/GeoLite*
}
export -f hub_purge_all

# remove unused data from the index, to make sure we don't rely on it in any way
hub_strip_index() {
    local INDEX
    INDEX=$(config_get .config_paths.index_path)
    local hub_min
    hub_min=$(jq <"$INDEX" 'del(..|.content?) | del(..|.long_description?) | del(..|.deprecated?) | del (..|.labels?)')
    echo "$hub_min" >"$INDEX"
}
export -f hub_strip_index

# remove color and style sequences from stdin
plaintext() {
    sed -E 's/\x1B\[[0-9;]*[JKmsu]//g'
}
export -f plaintext

# like run but defaults to separate stderr and stdout
rune() {
    run --separate-stderr "$@"
}
export -f rune
