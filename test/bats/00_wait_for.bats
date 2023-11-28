#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

@test "run a command and capture its stdout" {
    run -0 wait-for seq 1 3
    assert_output - <<-EOT
	1
	2
	3
	EOT
}

@test "run a command and capture its stderr" {
    rune -0 wait-for sh -c 'seq 1 3 >&2'
    assert_stderr - <<-EOT
	1
	2
	3
	EOT
}

@test "run a command until a pattern is found in stdout" {
    run -0 wait-for --out "1[12]0" seq 1 200
    assert_line --index 0 "1"
    assert_line --index -1 "110"
    refute_line "111"
}

@test "run a command until a pattern is found in stderr" {
    rune -0 wait-for --err "10" sh -c 'seq 1 20 >&2'
    assert_stderr - <<-EOT
	1
	2
	3
	4
	5
	6
	7
	8
	9
	10
	EOT
}

@test "run a command with timeout (no match)" {
    # when the process is terminated without a match, it returns
    # 256 - 15 (SIGTERM) = 241
    rune -241 wait-for --timeout 0.1 --out "10" sh -c 'echo 1; sleep 3; echo 2'
    assert_line 1
    # there may be more, but we don't care
}

@test "run a command with timeout (match)" {
    # when the process is terminated with a match, return code is 128
    rune -128 wait-for --timeout .4 --out "2" sh -c 'echo 1; sleep .1; echo 2; echo 3; echo 4; sleep 10'
    assert_output - <<-EOT
	1
	2
	EOT
}

