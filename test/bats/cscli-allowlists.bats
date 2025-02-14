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
    assert_stderr 'Error: accepts 1 arg(s), received 0'

    rune -1 cscli allowlist create foo
    assert_stderr 'Error: required flag(s) "description" not set'

    rune -0 cscli allowlist create foo -d "A Foo"
    assert_output "allowlist 'foo' created successfully"

    rune -1 cscli allowlist create foo -d "Another Foo"
    assert_stderr "Error: allowlist 'foo' already exists"

    rune -0 cscli allowlists list -o json
    rune -0 jq 'del(.[].created_at) | del(.[].updated_at)' <(output)
    assert_json '[{"description":"A Foo","items":[],"name":"foo"}]'

    rune -0 cscli allowlist create Foo -d "Another Foo"
    assert_output "allowlist 'Foo' created successfully"
}

@test "cscli allowlists add" {
    rune -1 cscli allowlist add
    assert_stderr 'Error: requires at least 2 arg(s), only received 0'

    rune -1 cscli allowlist add foo
    assert_stderr 'Error: requires at least 2 arg(s), only received 1'

    rune -1 cscli allowlist add foo bar
    assert_stderr "Error: allowlist 'foo' not found"

    rune -0 cscli allowlist create foo -d 'a foo'

    rune -0 cscli allowlist add foo bar
    # XXX: here we should return an error?
    # and it's currently displayed as ERRO[0000] -- client logger has no formatter?
    assert_stderr --partial "level=error msg=\"invalid ip address 'bar'\""
    refute_output

    rune -0 cscli allowlist add foo 1.1.1.256
    assert_stderr --partial "level=error msg=\"invalid ip address '1.1.1.256'\""
    refute_output

    rune -0 cscli allowlist add foo 1.1.1.1/2/3
    assert_stderr --partial "level=error msg=\"invalid ip range '1.1.1.1/2/3': invalid CIDR address: 1.1.1.1/2/3\""
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
    assert_stderr 'Error: time: invalid duration "toto"'
    refute_output

    rune -1 cscli allowlist add foo 10.10.10.10 10.20.30.40 -d comment -e '1 day'
    refute_output
    assert_stderr 'Error: strconv.Atoi: parsing "1 ": invalid syntax'

    rune -0 cscli allowlist add foo 10.10.10.10 -d comment -e '1d'
    assert_output 'added 1 values to allowlist foo'
    refute_stderr

    rune -0 cscli allowlist add foo 10.20.30.40 -d comment -e '30m'
    assert_output 'added 1 values to allowlist foo'
    refute_stderr
}

@test "cscli allowlists delete" {
    rune -1 cscli allowlist delete
    assert_stderr 'Error: accepts 1 arg(s), received 0'

    rune -1 cscli allowlist delete does-not-exist
    assert_stderr "Error: allowlist 'does-not-exist' not found"

    rune -0 cscli allowlist create foo -d "A Foo"
    rune -0 cscli allowlist add foo 1.2.3.4

    rune -0 cscli allowlist delete foo
    assert_output "allowlist 'foo' deleted successfully"
    refute_stderr
}

@test "cscli allowlists inspect" {
    rune -1 cscli allowlist inspect
    assert_stderr 'Error: accepts 1 arg(s), received 0'

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
    assert_stderr 'Error: requires at least 2 arg(s), only received 0'

    rune -1 cscli allowlist remove foo
    assert_stderr 'Error: requires at least 2 arg(s), only received 1'

    rune -1 cscli allowlist remove foo 1.2.3.4
    assert_stderr "Error: allowlist 'foo' not found"

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
