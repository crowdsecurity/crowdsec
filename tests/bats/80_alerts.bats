#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
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

@test "cscli alerts list, with and without --machine" {
    is_db_postgres && skip
    run -0 cscli decisions add -i 10.20.30.40 -t ban

    run -0 cscli alerts list
    refute_output --partial 'machine'
    # machine name appears quoted in the "REASON" column
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    refute_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    run -0 cscli alerts list -m
    assert_output --partial 'machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "

    run -0 cscli alerts list --machine
    assert_output --partial 'machine'
    assert_output --regexp " 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?' "
    assert_output --regexp " githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})? "
}

@test "cscli alerts list, human/json/raw" {
    run -0 cscli decisions add -i 10.20.30.40 -t ban

    run -0 cscli alerts list -o human
    run -0 plaintext < <(output)
    assert_output --regexp ".* ID .* value .* reason .* country .* as .* decisions .* created_at .*"
    assert_output --regexp ".*Ip:10.20.30.40.*manual 'ban' from.*ban:1.*"

    run -0 cscli alerts list -o json
    run -0 jq -c '.[].decisions[0] | [.origin, .scenario, .scope, .simulated, .type, .value]' <(output)
    assert_line --regexp "\[\"cscli\",\"manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?'\",\"Ip\",false,\"ban\",\"10.20.30.40\"\]"

    run -0 cscli alerts list -o raw
    assert_line "id,scope,value,reason,country,as,decisions,created_at"
    assert_line --regexp ".*,Ip,10.20.30.40,manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?',,\" \",ban:1,.*"

    run -0 cscli alerts list -o raw --machine
    assert_line "id,scope,value,reason,country,as,decisions,created_at,machine"
    assert_line --regexp "^[0-9]+,Ip,10.20.30.40,manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?',,\" \",ban:1,.*,githubciXXXXXXXXXXXXXXXXXXXXXXXX([a-zA-Z0-9]{16})?$"
}

@test "cscli alerts inspect" {
    run -0 cscli decisions add -i 10.20.30.40 -t ban
    run -0 cscli alerts list -o raw <(output)
    run -0 grep 10.20.30.40 <(output)
    run -0 cut -d, -f1 <(output)
    ALERT_ID="${output}"

    run -0 cscli alerts inspect "${ALERT_ID}" -o human
    run -0 plaintext < <(output)
    assert_line --regexp '^#+$'
    assert_line --regexp "^ - ID *: ${ALERT_ID}$"
    assert_line --regexp "^ - Date *: .*$"
    assert_line --regexp "^ - Machine *: githubciXXXXXXXXXXXXXXXXXXXXXXXX.*"
    assert_line --regexp "^ - Simulation *: false$"
    assert_line --regexp "^ - Reason *: manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX.*'$"
    assert_line --regexp "^ - Events Count *: 1$"
    assert_line --regexp "^ - Scope:Value *: Ip:10.20.30.40$"
    assert_line --regexp "^ - Country *: *$"
    assert_line --regexp "^ - AS *: *$"
    assert_line --regexp "^ - Begin *: .*$"
    assert_line --regexp "^ - End *: .*$"
    assert_line --regexp "^ - Active Decisions *:$"
    assert_line --regexp "^.* ID .* scope:value .* action .* expiration .* created_at .*$"
    assert_line --regexp "^.* Ip:10.20.30.40 .* ban .*$"

    run -0 cscli alerts inspect "${ALERT_ID}" -o human --details
    # XXX can we have something here?

    run -0 cscli alerts inspect "${ALERT_ID}" -o raw
    assert_line --regexp "^ *capacity: 0$"
    assert_line --regexp "^ *id: ${ALERT_ID}$"
    assert_line --regexp "^ *origin: cscli$"
    assert_line --regexp "^ *scenario: manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX.*'$"
    assert_line --regexp "^ *scope: Ip$"
    assert_line --regexp "^ *simulated: false$"
    assert_line --regexp "^ *type: ban$"
    assert_line --regexp "^ *value: 10.20.30.40$"

    run -0 cscli alerts inspect "${ALERT_ID}" -o json
    alert=${output}
    run jq -c '.decisions[] | [.origin,.scenario,.scope,.simulated,.type,.value]' <<<"${alert}"
    assert_output --regexp "\[\"cscli\",\"manual 'ban' from 'githubciXXXXXXXXXXXXXXXXXXXXXXXX.*'\",\"Ip\",false,\"ban\",\"10.20.30.40\"\]"
    run jq -c '.source' <<<"${alert}"
    assert_json '{ip:"10.20.30.40",scope:"Ip",value:"10.20.30.40"}'
}

@test "no active alerts" {
    run -0 cscli alerts list --until 200d -o human
    assert_output "No active alerts"
    run -0 cscli alerts list --until 200d -o json
    assert_output "null"
    run -0 cscli alerts list --until 200d -o raw
    assert_output "id,scope,value,reason,country,as,decisions,created_at"
    run -0 cscli alerts list --until 200d -o raw --machine
    assert_output "id,scope,value,reason,country,as,decisions,created_at,machine"
}

@test "cscli alerts delete (by id)" {
    # make sure there is at least one alert
    run -0 cscli decisions add -i 127.0.0.1 -d 1h -R crowdsecurity/test
    # when testing with global config, alert id is not guaranteed to be 1.
    # we'll just remove the first alert we find
    run -0 --separate-stderr cscli alerts list -o json
    run -0 jq -c '.[0].id' <(output)
    ALERT_ID="$output"

    run -0 --separate-stderr cscli alerts delete --id "$ALERT_ID"
    refute_output
    assert_stderr --partial "1 alert(s) deleted"

    # can't delete twice
    run -1 --separate-stderr cscli alerts delete --id "$ALERT_ID"
    refute_output
    assert_stderr --partial "Unable to delete alert"
    assert_stderr --partial "API error: ent: alert not found"
}

@test "cscli alerts delete (all)" {
    run -0 --separate-stderr cscli alerts delete --all
    assert_stderr --partial '0 alert(s) deleted'

    run -0 cscli decisions add -i 1.2.3.4 -d 1h -R crowdsecurity/test
    run -0 cscli decisions add -i 1.2.3.5 -d 1h -R crowdsecurity/test

    run -0 --separate-stderr cscli alerts delete --all
    assert_stderr --partial '2 alert(s) deleted'

    # XXX TODO: delete by scope, value, scenario, range..
}

@test "cscli alerts delete (with cascade to decisions)" {
    run -0 cscli decisions add -i 1.2.3.4
    run -0 --separate-stderr cscli decisions list -o json
    run -0 jq '. | length' <(output)
    assert_output 1

    run -0 --separate-stderr cscli alerts delete -i 1.2.3.4
    assert_stderr --partial 'alert(s) deleted'
    run -0 --separate-stderr cscli decisions list -o json
    assert_output null
}

@test "cscli alerts delete (must ignore the query limit)" {
    for i in $(seq 1 200); do
        run -0 cscli decisions add -i 1.2.3.4
    done
    run -0 --separate-stderr cscli alerts delete -i 1.2.3.4
    assert_stderr --partial '200 alert(s) deleted'
}

@test "bad duration" {
    skip 'TODO'
    run -0 cscli decisions add -i 10.20.30.40 -t ban
    run -9 --separate-stderr cscli decisions list --ip 10.20.30.40 -o json
    run -9 jq -r '.[].decisions[].id' <(output)
    DECISION_ID="${output}"

    ./instance-crowdsec stop
    run -0 ./instance-db exec_sql "UPDATE decisions SET ... WHERE id=${DECISION_ID}"
    ./instance-crowdsec start
}
