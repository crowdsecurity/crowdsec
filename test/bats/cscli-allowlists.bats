#!/usr/bin/env bats

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

#----------

@test "cscli allowlists list (empty)" {
    rune -0 cscli allowlists list
    assert_output - <<-EOT
	---------------------------------------------------------------------
	 Name  Description  Created at  Updated at  Managed by Console  Size 
	---------------------------------------------------------------------
	---------------------------------------------------------------------
	EOT

    rune -0 cscli allowlists list -o raw
    assert_output 'name,description,created_at,updated_at,console_managed,size'

    rune -0 cscli allowlists list -o json
    assert_json '[]'

    # sub-command alias, like "decisions", "collections..."
    rune -0 cscli allowlist list -o json
    assert_json '[]'

    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 1.1.1.1

    rune -0 cscli allowlists list
    assert_output - --regexp <<-EOT
	--------------------.*
	 Name  Description  .* Managed by Console  Size 
	--------------------.*
	 foo   a foo        .* no                     1 
	--------------------.*
	EOT

    # requires LAPI
    ./instance-crowdsec stop
    rune -1 wait-for --err 'error while performing request' "$CSCLI" allowlists list
}

@test "cscli allowlists create" {
    rune -1 cscli allowlist create
    assert_stderr 'Error: cscli allowlists create: accepts 1 arg(s), received 0'

    rune -1 cscli allowlist create foo
    assert_stderr 'Error: cscli allowlists create: required flag(s) "description" not set'

    rune -0 cscli allowlist create foo -d "A Foo"
    assert_output "allowlist 'foo' created successfully"

    rune -1 cscli allowlist create foo -d "Another Foo"
    assert_stderr "Error: cscli allowlists create: allowlist 'foo' already exists"

    rune -0 cscli allowlists list -o json
    rune -0 jq 'del(.[].created_at) | del(.[].updated_at)' <(output)
    assert_json '[{"description":"A Foo","items":[],"name":"foo"}]'

    rune -0 cscli allowlist create Foo -d "Another Foo"
    assert_output "allowlist 'Foo' created successfully"
}

@test "cscli allowlists add" {
    rune -1 cscli allowlist add
    assert_stderr 'Error: cscli allowlists add: requires at least 2 arg(s), only received 0'

    rune -1 cscli allowlist add foo
    assert_stderr 'Error: cscli allowlists add: requires at least 2 arg(s), only received 1'

    rune -1 cscli allowlist add foo bar
    assert_stderr "Error: cscli allowlists add: allowlist 'foo' not found"

    rune -0 cscli allowlist create foo -d 'a foo'

    rune -0 cscli allowlist add foo bar
    # XXX: here we should return an error?
    # and it's currently displayed as ERRO[0000] -- client logger has no formatter?
    assert_stderr --partial 'level=error msg="ParseAddr(\"bar\"): unable to parse IP'
    refute_output

    rune -0 cscli allowlist add foo 1.1.1.256
    assert_stderr --partial 'level=error msg="ParseAddr(\"1.1.1.256\"): IPv4 field has value >255"'
    refute_output

    rune -0 cscli allowlist add foo 1.1.1.1/2/3
    assert_stderr --partial 'level=error msg="netip.ParsePrefix(\"1.1.1.1/2/3\"): ParseAddr(\"1.1.1.1/2\"): unexpected character (at \"/2\")"'
    refute_output

    rune -0 cscli allowlist add foo 1.2.3.4
    refute_stderr
    assert_output 'added 1 values to allowlist foo'

    rune -0 cscli allowlist add foo 1.2.3.4
    assert_stderr --partial 'level=warning msg="value 1.2.3.4 already in allowlist"'
    assert_output 'no new values for allowlist'

    rune -0 cscli allowlist add foo 5.6.7.8/24 9.10.11.12
    assert_output 'added 2 values to allowlist foo'

    # comment and expiration are applied to all values
    rune -1 cscli allowlist add foo 10.10.10.10 10.20.30.40 -d comment -e toto
    assert_stderr 'Error: cscli allowlists add: invalid argument "toto" for "-e, --expiration" flag: time: invalid duration "toto"'
    refute_output

    rune -1 cscli allowlist add foo 10.10.10.10 10.20.30.40 -d comment -e '1 day'
    refute_output
    assert_stderr 'Error: cscli allowlists add: invalid argument "1 day" for "-e, --expiration" flag: invalid day value in duration "1 day"'

    rune -0 cscli allowlist add foo 10.10.10.10 -d comment -e '1d12h'
    assert_output 'added 1 values to allowlist foo'
    refute_stderr

    rune -0 cscli allowlist add foo 10.20.30.40 -d comment -e '30m'
    assert_output 'added 1 values to allowlist foo'
    refute_stderr
}

@test "cscli allowlists: check during decisions add" {
    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 192.168.0.0/16
    rune -1 cscli decisions add -i 192.168.1.1
    assert_stderr 'Error: cscli decisions add: 192.168.1.1 is allowlisted by item 192.168.0.0/16 from foo, use --bypass-allowlist to add the decision anyway'
    refute_output
    rune -0 cscli decisions add -i 192.168.1.1 --bypass-allowlist
    assert_stderr --partial 'Decision successfully added'
    refute_output
}

@test "cscli allowlists: check during decisions import" {
    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 192.168.0.0/16
    rune -0 cscli decisions import -i - <<<'192.168.1.1' --format values
    assert_output - <<-EOT
	Parsing values
	Value 192.168.1.1 is allowlisted by [192.168.0.0/16 from foo]
	Imported 0 decisions
	EOT
    refute_stderr
}

@test "cscli allowlists: range check" {
    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 192.168.0.0/16
    rune -1 cscli decisions add -r 192.168.10.20/24
    assert_stderr --partial '192.168.10.20/24 is allowlisted by item 192.168.0.0/16 from foo, use --bypass-allowlist to add the decision anyway'
    rune -0 cscli decisions add -r 192.168.10.20/24 --bypass-allowlist
    assert_stderr --partial 'Decision successfully added'
}

@test "cscli allowlist: check lowercase range decisions import" {
    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 192.168.0.0/16
    rune -0 cscli decisions import -i - <<<'192.168.0.0/24' --format values --scope range 
    assert_output - <<-EOT
	Parsing values
	Value 192.168.0.0/24 is allowlisted by [192.168.0.0/16 from foo]
	Imported 0 decisions
	EOT
    refute_stderr
}

@test "cscli allowlists check" {
    rune -0 cscli allowlist create foo -d 'a foo'
    rune -0 cscli allowlist add foo 192.168.0.0/16
    rune -0 cscli allowlist check 192.168.0.1
    assert_output "192.168.0.1 is allowlisted by item 192.168.0.0/16 from foo"
    rune -0 cscli allowlist check 192.169.0.1
    assert_output "192.169.0.1 is not allowlisted"
    rune -0 cscli allowlist create bar -d 'a bar'
    rune -0 cscli allowlist add bar 192.168.0.0/24
    rune -0 cscli allowlist create Uppercase -d 'a uppercase'
    rune -0 cscli allowlist add Uppercase 192.168.0.0/28
    rune -0 cscli allowlist check 192.168.0.1 1.1.1.1
    assert_line "192.168.0.1 is allowlisted by item 192.168.0.0/28 from Uppercase, 192.168.0.0/24 from bar, 192.168.0.0/16 from foo"
    assert_line "1.1.1.1 is not allowlisted"
    refute_stderr
}
@test "cscli allowlists delete" {
    rune -1 cscli allowlist delete
    assert_stderr 'Error: cscli allowlists delete: accepts 1 arg(s), received 0'

    rune -1 cscli allowlist delete does-not-exist
    assert_stderr "Error: cscli allowlists delete: allowlist 'does-not-exist' not found"

    rune -0 cscli allowlist create foo -d "A Foo"
    rune -0 cscli allowlist add foo 1.2.3.4

    rune -0 cscli allowlist delete foo
    assert_output "allowlist 'foo' deleted successfully"
    refute_stderr
}

@test "cscli allowlists inspect" {
    rune -1 cscli allowlist inspect
    assert_stderr 'Error: cscli allowlists inspect: accepts 1 arg(s), received 0'

    rune -0 cscli allowlist create foo -d "A Foo"
    assert_output "allowlist 'foo' created successfully"

    rune -0 cscli allowlist add foo 1.2.3.4

    rune -0 cscli allowlist inspect foo
    assert_output - --regexp <<-EOT
	---------------------.*
	 Allowlist: foo      .*
	---------------------.*
	 Name                foo   .*
	 Description         A Foo .*
	 Created at          .*
	 Updated at          .*
	 Managed by Console  no .*
	---------------------.*
	------------------------------------------.*
	 Value    Comment  Expiration  Created at .*
	------------------------------------------.*
	 1.2.3.4           never       .*
	------------------------------------------.*
	EOT

    rune -0 cscli allowlist inspect foo -o raw
    assert_output - --regexp <<-EOT
	name,description,value,comment,expiration,created_at,console_managed
	foo,A Foo,1.2.3.4,,never,.*,false
	EOT

    rune -0 cscli allowlist inspect foo -o json
    rune -0 jq 'del(.created_at) | del(.updated_at) | del(.items.[].created_at) | del(.items.[].expiration)' <(output)
    assert_json '{"description":"A Foo","items":[{"value":"1.2.3.4"}],"name":"foo"}'
}

@test "cscli allowlists remove" {
    rune -1 cscli allowlist remove
    assert_stderr 'Error: cscli allowlists remove: requires at least 2 arg(s), only received 0'

    rune -1 cscli allowlist remove foo
    assert_stderr 'Error: cscli allowlists remove: requires at least 2 arg(s), only received 1'

    rune -1 cscli allowlist remove foo 1.2.3.4
    assert_stderr "Error: cscli allowlists remove: allowlist 'foo' not found"

    rune -0 cscli allowlist create foo -d 'a foo'
    # no error, should be ok
    rune -0 cscli allowlist remove foo 1.2.3.4
    assert_output 'no value to remove from allowlist'

    rune -0 cscli allowlist add foo 1.2.3.4 5.6.7.8
    rune -0 cscli allowlist remove foo 1.2.3.4
    assert_output 'removed 1 values from allowlist foo'

    rune -0 cscli allowlist remove foo 1.2.3.4 5.6.7.8
    refute_stderr
    assert_output 'removed 1 values from allowlist foo'
    rune -0 cscli allowlist inspect foo -o json
    rune -0 jq 'del(.created_at) | del(.updated_at) | del(.items.[].created_at) | del(.items.[].expiration)' <(output)
    assert_json '{"description":"a foo","items":[],"name":"foo"}'
}

@test "allowlists expire active decisions" {
    rune -0 cscli decisions add -i 1.2.3.4
    rune -0 cscli decisions add -r 2.3.4.0/24
    rune -0 cscli decisions add -i 5.4.3.42
    rune -0 cscli decisions add -r 6.5.4.0/24
    rune -0 cscli decisions add -r 10.0.0.0/23

    rune -0 cscli decisions list -o json
    rune -0 jq -r 'sort_by(.decisions[].value) | .[].decisions[0].value' <(output)
    assert_output - <<-EOT
	1.2.3.4
	10.0.0.0/23
	2.3.4.0/24
	5.4.3.42
	6.5.4.0/24
	EOT

    rune -0 cscli allowlists create foo -d "foo"

    # add an allowlist that matches exactly
    rune -0 cscli allowlists add foo 1.2.3.4
    if is_db_mysql; then sleep 2; fi
    # it should not be here anymore
    rune -0 cscli decisions list -o json
    rune -0 jq -e 'any(.[].decisions[]; .value == "1.2.3.4") | not' <(output)

    # allowlist an IP belonging to a range
    rune -0 cscli allowlist add foo 2.3.4.42
    if is_db_mysql; then sleep 2; fi
    rune -0 cscli decisions list -o json
    rune -0 jq -e 'any(.[].decisions[]; .value == "2.3.4.0/24") | not' <(output)

    # allowlist a range with an active decision inside
    rune -0 cscli allowlist add foo 5.4.3.0/24
    if is_db_mysql; then sleep 2; fi
    rune -0 cscli decisions list -o json
    rune -0 jq -e 'any(.[].decisions[]; .value == "5.4.3.42") | not' <(output)

    # allowlist a range inside a range for which we have a decision
    rune -0 cscli allowlist add foo 6.5.4.0/25
    if is_db_mysql; then sleep 2; fi
    rune -0 cscli decisions list -o json
    rune -0 jq -e 'any(.[].decisions[]; .value == "6.5.4.0/24") | not' <(output)

    # allowlist a range bigger than a range for which we have a decision
    rune -0 cscli allowlist add foo 10.0.0.0/24
    if is_db_mysql; then sleep 2; fi
    rune -0 cscli decisions list -o json
    rune -0 jq -e 'any(.[].decisions[]; .value == "10.0.0.0/24") | not' <(output)

    # sanity check no more active decisions
    rune -0 cscli decisions list -o json
    assert_json []
}
