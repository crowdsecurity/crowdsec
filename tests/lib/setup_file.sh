
# Allow tests to use relative paths for helper scripts.
# Must redirect output to &3 otherwise errors in setup_file, teardown_file go unreported

# shellcheck disable=SC2164
cd "${TEST_DIR}" >&3 2>&1

# complain if there's a crowdsec running system-wide or leftover from a previous test
./assert-crowdsec-not-running

# we can use the filename in test descriptions
FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
export FILE

# the variables exported here can be seen in other setup/teardown/test functions
CROWDSEC="${BIN_DIR}/crowdsec"
export CROWDSEC
CSCLI="${BIN_DIR}/cscli"
export CSCLI

# functions too
cscli() {
    "${CSCLI}" "$@"
}
export -f cscli

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
