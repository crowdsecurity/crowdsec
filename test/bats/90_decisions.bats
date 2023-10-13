#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"

    TESTDATA="${BATS_TEST_DIRNAME}/testdata/90_decisions"
    export TESTDATA
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "'decisions add' requires parameters" {
    rune -1 cscli decisions add
    assert_line "Usage:"
    assert_stderr --partial "Missing arguments, a value is required (--ip, --range or --scope and --value)"

    rune -1 cscli decisions add -o json
    rune -0 jq -c '[ .level, .msg]' <(stderr | grep "^{")
    assert_output '["fatal","Missing arguments, a value is required (--ip, --range or --scope and --value)"]'
}

@test "cscli decisions list, with and without --machine" {
    is_db_postgres && skip
    rune -0 cscli decisions add -i 10.20.30.40 -t ban

    rune -0 cscli decisions list
    refute_output --partial 'Machine'
    # machine name appears quoted in the "REASON" column
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    refute_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    rune -0 cscli decisions list -m
    assert_output --partial 'Machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    rune -0 cscli decisions list --machine
    assert_output --partial 'Machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "
}

@test "cscli decisions list, incorrect parameters" {
    rune -1 cscli decisions list --until toto
    assert_stderr --partial 'unable to retrieve decisions: performing request: API error: while parsing duration: time: invalid duration \"toto\"'
    rune -1 cscli decisions list --until toto -o json
    rune -0 jq -c '[.level, .msg]' <(stderr | grep "^{")
    assert_output '["fatal","unable to retrieve decisions: performing request: API error: while parsing duration: time: invalid duration \"toto\""]'
}

@test "cscli decisions import" {
    # required input
    rune -1 cscli decisions import
    assert_stderr --partial 'required flag(s) \"input\" not set"'

    # unsupported format
    rune -1 cscli decisions import -i - <<<'value\n5.6.7.8' --format xml
    assert_stderr --partial "invalid format 'xml', expected one of 'json', 'csv', 'values'"

    # invalid defaults
    rune -1 cscli decisions import --duration "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "--duration cannot be empty"
    rune -1 cscli decisions import --scope "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "--scope cannot be empty"
    rune -1 cscli decisions import --reason "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "--reason cannot be empty"
    rune -1 cscli decisions import --type "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "--type cannot be empty"

    #----------
    # JSON
    #----------

    # import from file
    rune -1 cscli decisions import -i "${TESTDATA}/json_decisions"
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"

    rune -0 cscli decisions import -i "${TESTDATA}/decisions.json"
    assert_stderr --partial "Parsing json"
    assert_stderr --partial "Imported 5 decisions"

    # import from stdin
    rune -1 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.json")
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"
    rune -0 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.json") --format json
    assert_stderr --partial "Parsing json"
    assert_stderr --partial "Imported 5 decisions"

    # invalid json
    rune -1 cscli decisions import -i - <<<'{"blah":"blah"}' --format json
    assert_stderr --partial 'Parsing json'
    assert_stderr --partial 'json: cannot unmarshal object into Go value of type []main.decisionRaw'

    # json with extra data
    rune -1 cscli decisions import -i - <<<'{"values":"1.2.3.4","blah":"blah"}' --format json
    assert_stderr --partial 'Parsing json'
    assert_stderr --partial 'json: cannot unmarshal object into Go value of type []main.decisionRaw'

    #----------
    # CSV
    #----------

    # import from file
    rune -1 cscli decisions import -i "${TESTDATA}/csv_decisions"
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"

    rune -0 cscli decisions import -i "${TESTDATA}/decisions.csv"
    assert_stderr --partial 'Parsing csv'
    assert_stderr --partial 'Imported 5 decisions'

    # import from stdin
    rune -1 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.csv")
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"
    rune -0 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.csv") --format csv
    assert_stderr --partial "Parsing csv"
    assert_stderr --partial "Imported 5 decisions"

    # invalid csv
    # XXX: improve validation
    rune -0 cscli decisions import -i - <<<'value\n1.2.3.4,5.6.7.8' --format csv
    assert_stderr --partial 'Parsing csv'
    assert_stderr --partial "Imported 0 decisions"

    #----------
    # VALUES
    #----------

    # can use '-' as stdin
    rune -0 cscli decisions import -i - --format values <<-EOT
	1.2.3.4
	1.2.3.5
	1.2.3.6
	EOT
    assert_stderr --partial 'Parsing values'
    assert_stderr --partial 'Imported 3 decisions'

    rune -0 cscli decisions import -i - --format values <<-EOT
	  10.2.3.4  
	10.2.3.5   
	   10.2.3.6
	EOT
    assert_stderr --partial 'Parsing values'
    assert_stderr --partial 'Imported 3 decisions'

    rune -1 cscli decisions import -i - --format values <<-EOT
	whatever
	EOT
    assert_stderr --partial 'Parsing values'
    assert_stderr --partial 'creating alert decisions: whatever: invalid ip address / range'

    #----------
    # Batch
    #----------

    rune -0 cscli decisions import -i - --format values --batch 2 --debug <<-EOT
	1.2.3.4
	1.2.3.5
	1.2.3.6
	EOT
    assert_stderr --partial 'Processing chunk of 2 decisions'
    assert_stderr --partial 'Processing chunk of 1 decisions'
    assert_stderr --partial 'Imported 3 decisions'
}
