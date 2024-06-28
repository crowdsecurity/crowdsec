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

@test "usage metrics (empty payload)" {
    # a registered log processor can send metrics for the console
    token=$(lp_login)
    usage_metrics="http://localhost:8080/v1/usage-metrics"

    payload=$(cat <<-EOT
	remediation_components: []
	log_processors: []
	EOT
    )

    rune -0 curl -sS -H "Authorization: Bearer ${token}" -X POST "$usage_metrics" --data "$(echo "$payload" | yq -o j)"
    refute_output
    refute_stderr
}

@test "usage metrics (bad payload)" {
    token=$(lp_login)
    usage_metrics="http://localhost:8080/v1/usage-metrics"

    payload=$(cat <<-EOT
	remediation_components: []
	log_processors:
	    - version: "v1.0"
	EOT
    )

    rune -22 curl -f -sS -H "Authorization: Bearer ${token}" -X POST "$usage_metrics" --data "$(echo "$payload" | yq -o j)"
    assert_stderr "curl: (22) The requested URL returned error: 422"

    rune -0 curl -sS -H "Authorization: Bearer ${token}" -X POST "$usage_metrics" --data "$(echo "$payload" | yq -o j)"
    rune -0 jq -r '.message' <(output)
    assert_output - <<-EOT
	validation failure list:
	log_processors.0.utc_startup_timestamp in body is required
	log_processors.0.datasources in body is required
	log_processors.0.hub_items in body is required
	EOT

}

@test "usage metrics (full payload)" {
    token=$(lp_login)
    usage_metrics="http://localhost:8080/v1/usage-metrics"

    payload=$(cat <<-EOT
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

    rune -0 curl -sS -H "Authorization: Bearer ${token}" -X POST "$usage_metrics" --data "$(echo "$payload" | yq -o j)"
    refute_output
}
