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

@test "cscli metrics show bouncers" {
    # there are no bouncers, so no metrics yet
    rune -0 cscli metrics show bouncers
    refute_output
}

@test "rc usage metrics (empty payload)" {
    # a registered bouncer can send metrics for the lapi and console
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components: []
	log_processors: []
	EOT
    )

    rune -22 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial 'error: 400'
    assert_json '{message: "Missing remediation component data"}'
}

@test "rc usage metrics (bad payload)" {
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	    - version: "v1.0"
	log_processors: []
	EOT
    )

    rune -22 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial "error: 422"
    rune -0 jq -r '.message' <(output)
    assert_output - <<-EOT
	validation failure list:
	remediation_components.0.utc_startup_timestamp in body is required
	EOT

    # validation, like timestamp format

    payload=$(yq -o j '.remediation_components[0].utc_startup_timestamp = "2021-09-01T00:00:00Z"' <<<"$payload")
    rune -22 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial "error: 400"
    assert_json '{message: "json: cannot unmarshal string into Go struct field AllMetrics.remediation_components of type int64"}'

    payload=$(yq -o j '.remediation_components[0].utc_startup_timestamp = 1707399316' <<<"$payload")
    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    refute_output
}

@test "rc usage metrics (good payload)" {
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	    - version: "v1.0"
	      utc_startup_timestamp: 1707399316
	log_processors: []
	EOT
    )

    # bouncers have feature flags too

    payload=$(yq -o j '
        .remediation_components[0].feature_flags = ["huey", "dewey", "louie"] |
        .remediation_components[0].os = {"name": "Multics", "version": "MR12.5"}
    ' <<<"$payload")
    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    rune -0 cscli bouncer inspect testbouncer -o json
    rune -0 yq -o j '[.os,.featureflags]' <(output)
    assert_json '["Multics/MR12.5",["huey","dewey","louie"]]'

    payload=$(yq -o j '
        .remediation_components[0].metrics = [
        {
            "meta": {"utc_now_timestamp": 1707399316, "window_size_seconds":600},
            "items":[
                {"name": "foo", "unit": "pound", "value": 3.1415926},
                {"name": "foo", "unit": "pound", "value": 2.7182818},
                {"name": "foo", "unit": "dogyear", "value": 2.7182818}
            ]
        }
        ]
    ' <<<"$payload")
    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    rune -0 cscli metrics show bouncers -o json
    # aggregation is ok -- we are truncating, not rounding, because the float is mandated by swagger.
    # but without labels the origin string is empty
    assert_json '{bouncers:{testbouncer:{"": {"foo": {"dogyear": 2, "pound": 5}}}}}'

    # TODO: adjust the table output
    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT

	Bouncer Metrics (testbouncer):
	+--+---------------------+---------------------+
	|  |        Bytes        |       Packets       |
	|  | processed | dropped | processed | dropped |
	+--+-----------+---------+-----------+---------+
	|  |       NaN |     NaN |       NaN |     NaN |
	+--+-----------+---------+-----------+---------+
	EOT
}
