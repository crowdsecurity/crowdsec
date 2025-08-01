#!/usr/bin/env bats

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
    load "../lib/bats-file/load.bash"
    ./instance-data load
    LOGFILE=$(config_get '.common.log_dir')/crowdsec.log
    export LOGFILE
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "'decisions add' requires parameters" {
    rune -1 cscli decisions add
    assert_stderr "Error: cscli decisions add: missing arguments, a value is required (--ip, --range or --scope and --value)"
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

@test "cscli decisions list, accept duration parameters with days" {
    rune -1 cscli decisions list --until toto
    assert_stderr 'Error: cscli decisions list: invalid argument "toto" for "--until" flag: time: invalid duration "toto"'
    rune -0 cscli decisions list --until 2d12h --debug
    assert_stderr --partial "until=60h0m0s"
    rune -0 cscli decisions list --since 2d12h --debug
    assert_stderr --partial "since=60h0m0s"
}

@test "cscli decisions import" {
    # required input
    rune -1 cscli decisions import
    assert_stderr 'Error: cscli decisions import: required flag(s) "input" not set'

    # unsupported format
    rune -1 cscli decisions import -i - <<<'value\n5.6.7.8' --format xml
    assert_stderr --partial "invalid format 'xml', expected one of 'json', 'csv', 'values'"

    # invalid defaults
    rune -1 cscli decisions import --duration "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "default duration cannot be empty"
    rune -1 cscli decisions import --scope "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "default scope cannot be empty"
    rune -1 cscli decisions import --reason "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "default reason cannot be empty"
    rune -1 cscli decisions import --type "" -i - <<<'value\n5.6.7.8' --format csv
    assert_stderr --partial "default type cannot be empty"

    #----------
    # JSON
    #----------

    # import from file
    rune -1 cscli decisions import -i "${TESTDATA}/json_decisions"
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"

    rune -0 cscli decisions import -i "${TESTDATA}/decisions.json"
    assert_output --partial "Parsing json"
    assert_output --partial "Imported 5 decisions"

    # import from stdin
    rune -1 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.json")
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"
    rune -0 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.json") --format json
    assert_output --partial "Parsing json"
    assert_output --partial "Imported 5 decisions"

    # invalid json
    rune -1 cscli decisions import -i - <<<'{"blah":"blah"}' --format json
    assert_output --partial 'Parsing json'
    assert_stderr --partial 'json: cannot unmarshal object into Go value of type []clidecision.decisionRaw'

    # json with extra data
    rune -1 cscli decisions import -i - <<<'{"values":"1.2.3.4","blah":"blah"}' --format json
    assert_output --partial 'Parsing json'
    assert_stderr --partial 'json: cannot unmarshal object into Go value of type []clidecision.decisionRaw'

    #----------
    # CSV
    #----------

    # import from file
    rune -1 cscli decisions import -i "${TESTDATA}/csv_decisions"
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"

    rune -0 cscli decisions import -i "${TESTDATA}/decisions.csv"
    assert_output --partial 'Parsing csv'
    assert_output --partial 'Imported 5 decisions'

    # import from stdin
    rune -1 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.csv")
    assert_stderr --partial "unable to guess format from file extension, please provide a format with --format flag"
    rune -0 cscli decisions import -i /dev/stdin < <(cat "${TESTDATA}/decisions.csv") --format csv
    assert_output --partial "Parsing csv"
    assert_output --partial "Imported 5 decisions"

    # invalid csv
    # XXX: improve validation
    rune -1 cscli decisions import -i - <<<'value\n1.2.3.4,5.6.7.8' --format csv
    assert_output "Parsing csv"
    assert_stderr "Error: cscli decisions import: no decisions found"

    #----------
    # VALUES
    #----------

    # can use '-' as stdin
    rune -0 cscli decisions import -i - --format values <<-EOT
	1.2.3.4
	1.2.3.5
	1.2.3.6
	EOT
    assert_output --partial 'Parsing values'
    assert_output --partial 'Imported 3 decisions'

    # leading or trailing spaces are ignored
    rune -0 cscli decisions import -i - --format values <<-EOT
	  10.2.3.4  
	10.2.3.5   
	   10.2.3.6
	EOT
    assert_output --partial 'Parsing values'
    assert_output --partial 'Imported 3 decisions'

    # silently discarding (but logging) invalid decisions

    rune -0 cscli alerts delete --all
    truncate -s 0 "$LOGFILE"

    rune -1 cscli decisions import -i - --format values <<-EOT
	whatever
	EOT
    assert_stderr --partial 'API error: ParseAddr("whatever"): unable to parse IP'

    rune -0 cscli decisions list -a -o json
    assert_json '[]'

    # disarding only some invalid decisions

    rune -0 cscli alerts delete --all
    truncate -s 0 "$LOGFILE"

    rune -1 cscli decisions import -i - --format values <<-EOT
        1.2.3.4
	bad-apple
        1.2.3.5
	EOT
    assert_output "Parsing values"
    assert_stderr 'Error: cscli decisions import: API error: ParseAddr("bad-apple"): unable to parse IP'

    rune -0 cscli decisions list -a -o json
    rune -0 jq -r '.[0].decisions | length' <(output)
    assert_output 0

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
    assert_output --partial 'Imported 3 decisions'
}
