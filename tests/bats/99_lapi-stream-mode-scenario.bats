#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    ./instance-crowdsec start
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY
    CROWDSEC_API_URL="http://localhost:8080"
    export CROWDSEC_API_URL
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

#----------

api() {
    URI="$1"
    curl -s -H "X-Api-Key:${API_KEY}" "${CROWDSEC_API_URL}${URI}"
}

output_new_decisions() {
    jq -c '.new | map(select(.origin!="CAPI")) | .[] | del(.id) | (.. | .duration?) |= capture("(?<d>[[:digit:]]+h[[:digit:]]+m)").d' <(output) | sort
}


@test "${FILE} adding decisions with different duration, scenario, origin" {
    # origin: test
    run -0 cscli decisions add -i 127.0.0.1 -d 1h -R crowdsecurity/test
    sleep 0.5
    ./instance-crowdsec stop
    run -0 ./instance-db exec_sql "update decisions set origin='test' where origin='cscli'"
    ./instance-crowdsec start

    run -0 cscli decisions add -i 127.0.0.1 -d 3h -R crowdsecurity/ssh_bf
    sleep 0.5
    ./instance-crowdsec stop
    run -0 ./instance-db exec_sql "update decisions set origin='another_origin' where origin='cscli'"
    ./instance-crowdsec start

    run -0 cscli decisions add -i 127.0.0.1 -d 5h -R crowdsecurity/longest
    sleep 0.5
    run -0 cscli decisions add -i 127.0.0.2 -d 3h -R crowdsecurity/test
    sleep 0.5
    run -0 cscli decisions add -i 127.0.0.2 -d 3h -R crowdsecurity/ssh_bf
    sleep 0.5
    run -0 cscli decisions add -i 127.0.0.2 -d 1h -R crowdsecurity/ssh_bf
    sleep 0.5
    ./instance-crowdsec stop
    run -0 ./instance-db exec_sql "update decisions set origin='test' where origin='cscli'"
    ./instance-crowdsec start

    # origin: another_origin
    run -0 cscli decisions add -i 127.0.0.2 -d 2h -R crowdsecurity/test
    sleep 0.5
    ./instance-crowdsec stop
    run -0 ./instance-db exec_sql "update decisions set origin='another_origin' where origin='cscli'"
    ./instance-crowdsec start
}

@test "${FILE} test startup" {
    run -0 api "/v1/decisions/stream?startup=true"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	{"duration":"4h59m","origin":"test","scenario":"crowdsecurity/longest","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with scenarios containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_containing=ssh_bf"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"another_origin","scenario":"crowdsecurity/ssh_bf","scope":"Ip","type":"ban","value":"127.0.0.1"}
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/ssh_bf","scope":"Ip","type":"ban","value":"127.0.0.2"}
	EOT
}

@test "${FILE} test startup with multiple scenarios containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_containing=ssh_bf,test"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"another_origin","scenario":"crowdsecurity/ssh_bf","scope":"Ip","type":"ban","value":"127.0.0.1"}
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	EOT
}

@test "${FILE} test startup with unknown scenarios containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_containing=unknown"
    assert_output '{"deleted":null,"new":null}'
}

@test "${FILE} test startup with scenarios containing and not containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_containing=test&scenarios_not_containing=ssh_bf"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	{"origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with scenarios containing and not containing 2" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_containing=longest&scenarios_not_containing=ssh_bf,test"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"4h59m","origin":"test","scenario":"crowdsecurity/longest","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with scenarios not containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh_bf"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	{"duration":"4h59m","origin":"test","scenario":"crowdsecurity/longest","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with multiple scenarios not containing" {
    run -0 api "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh_bf,test"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"4h59m","origin":"test","scenario":"crowdsecurity/longest","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with origins parameter" {
    run -0 api "/v1/decisions/stream?startup=true&origins=another_origin"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"1h59m","origin":"another_origin","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	{"duration":"2h59m","origin":"another_origin","scenario":"crowdsecurity/ssh_bf","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with multiple origins parameter" {
    run -0 api "/v1/decisions/stream?startup=true&origins=another_origin,test"
    run -0 output_new_decisions
    assert_output - <<-EOT
	{"duration":"2h59m","origin":"test","scenario":"crowdsecurity/test","scope":"Ip","type":"ban","value":"127.0.0.2"}
	{"duration":"4h59m","origin":"test","scenario":"crowdsecurity/longest","scope":"Ip","type":"ban","value":"127.0.0.1"}
	EOT
}

@test "${FILE} test startup with unknown origins" {
    run -0 api "/v1/decisions/stream?startup=true&origins=unknown"
    assert_output '{"deleted":null,"new":null}'
}

#@test "${FILE} delete decision 3 (127.0.0.1)" {
#
#        {
#            TestName:      "delete decisions 3 (127.0.0.1)",
#            Method:        "DELETE",
#            Route:         "/v1/decisions/3",
#            CheckCodeOnly: true,
#            Code:          200,
#            LenNew:        0,
#            LenDeleted:    0,
#            AuthType:      PASSWORD,
#            DelChecks:     []DecisionCheck{},
#            NewChecks:     []DecisionCheck{},
#       TestName:      "check that 127.0.0.1 is not in deleted IP",
#            Method:        "GET",
#            Route:         "/v1/decisions/stream?startup=true",
#            CheckCodeOnly: false,
#            Code:          200,
#            LenNew:        2,
#            LenDeleted:    0,
#            AuthType:      APIKEY,
#            DelChecks:     []DecisionCheck{},
#            NewChecks:     []DecisionCheck{},
#        },
#        {
#            TestName:      "delete decisions 2 (127.0.0.1)",
#            Method:        "DELETE",
#            Route:         "/v1/decisions/2",
#            CheckCodeOnly: true,
#            Code:          200,
#            LenNew:        0,
#            LenDeleted:    0,
#            AuthType:      PASSWORD,
#            DelChecks:     []DecisionCheck{},
#            NewChecks:     []DecisionCheck{},
#        },
#        {
#            TestName:      "check that 127.0.0.1 is not in deleted IP",
#            Method:        "GET",
#            Route:         "/v1/decisions/stream?startup=true",
#            CheckCodeOnly: false,
#            Code:          200,
#            LenNew:        2,
#            LenDeleted:    0,
#            AuthType:      APIKEY,
#            DelChecks:     []DecisionCheck{},
#            NewChecks:     []DecisionCheck{},
#        },
#        {
#            TestName:      "delete decisions 1 (127.0.0.1)",
#            Method:        "DELETE",
#            Route:         "/v1/decisions/1",
#            CheckCodeOnly: true,
#            Code:          200,
#            LenNew:        0,
#            LenDeleted:    0,
#            AuthType:      PASSWORD,
#            DelChecks:     []DecisionCheck{},
#            NewChecks:     []DecisionCheck{},
#        },
#            TestName:      "127.0.0.1 should be in deleted now",
#            Method:        "GET",
#            Route:         "/v1/decisions/stream?startup=true",
#            CheckCodeOnly: false,
#            Code:          200,
#            LenNew:        1,
#            LenDeleted:    1,
#            AuthType:      APIKEY,
#            DelChecks: []DecisionCheck{
#                {
#                    ID:       int64(1),
#                    Origin:   "test",
#                    Scenario: "crowdsecurity/test",
#                    Value:    "127.0.0.1",
#                    Duration: "-", // we check that the time is negative
#                },
#            },
#            NewChecks: []DecisionCheck{},
#        },
#}

