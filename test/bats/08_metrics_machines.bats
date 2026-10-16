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
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "lp usage metrics (empty payload)" {
    # a registered log processor can send metrics for the lapi and console
    TOKEN=$(lp-get-token)
    export TOKEN

    payload=$(yq -o j <<-EOT
	remediation_components: []
	log_processors: []
	EOT
    )

    rune -22 curl-with-token '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial 'error: 400'
    assert_json '{message: "Missing log processor data"}'
}

@test "lp usage metrics (bad payload)" {
    TOKEN=$(lp-get-token)
    export TOKEN

    payload=$(yq -o j <<-EOT
	remediation_components: []
	log_processors:
	    - version: "v1.0"
	EOT
    )

    rune -22 curl-with-token '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial "error: 422"
    rune -0 jq -r '.message' <(output)
    assert_output - <<-EOT
	validation failure list:
	log_processors.0.utc_startup_timestamp in body is required
	EOT
}

@test "lp usage metrics (full payload)" {
    TOKEN=$(lp-get-token)
    export TOKEN

    # base payload without any measurement

    payload=$(yq -o j <<-EOT
	remediation_components: []
	log_processors:
	    - version: "v1.0"
	      utc_startup_timestamp: 1707399316
	      hub_items: {}
	      feature_flags:
	          - marshmallows
	      os:
	        name: CentOS
	        version: "8"
	      metrics:
	        - name: logs_parsed
	          value: 5000
	          unit: count
	          labels: {}
	          items: []
	          meta:
	           window_size_seconds: 600
	           utc_now_timestamp: 1707485349
	      console_options:
	        - share_context
	      datasources:
	        syslog: 1
	        file: 4
	EOT
    )

    rune -0 curl-with-token '/v1/usage-metrics' -X POST --data "$payload"
    refute_output
}
