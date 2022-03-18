
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

# complain if there's a crowdsec running system-wide or leftover from a previous test
./assert-crowdsec-not-running

# we can use the filename in test descriptions
FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
export FILE

# the variables exported here can be seen in other setup/teardown/test functions
# MYVAR=something
# export MYVAR

# functions too
cscli() {
    "${CSCLI}" "$@"
}
export -f cscli

config_yq() {
    yq <"${CONFIG_YAML}" "$@"
}
export -f config_yq

# We use these functions like this:
#    somecommand <(stderr)
# to provide a standard input to "somecommand".
# The alternatives echo "$stderr" or <<<"$stderr"
# ("here string" in bash jargon)
# are worse because they add a newline,
# even if the variable is empty.

# shellcheck disable=SC2154
stderr() {
    printf '%s' "$stderr"
}
export -f stderr

# shellcheck disable=SC2154
output() {
    printf '%s' "$output"
}
export -f output

