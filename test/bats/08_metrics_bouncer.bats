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

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	Bouncer Metrics (testbouncer) since 2024-02-08 13:35:16 +0000 UTC:
	+--------+-----------------+
	| Origin |       foo       |
	|        | dogyear | pound |
	+--------+---------+-------+
	|        |       2 |     5 |
	+--------+---------+-------+
	|  Total |       2 |     5 |
	+--------+---------+-------+
	EOT

    # some more realistic values, at least for the labels
    # we don't use the same now_timestamp or the payload will be silently discarded

    payload=$(yq -o j '
        .remediation_components[0].metrics = [
        {
          "meta": {"utc_now_timestamp": 1707399916, "window_size_seconds":600},
          "items":[
            {"name": "active_decisions", "unit": "ip",     "value": 51936, "labels": {"ip_type": "ipv4", "origin": "lists:firehol_voipbl"}},
            {"name": "active_decisions", "unit": "ip",     "value": 1,     "labels": {"ip_type": "ipv6", "origin": "cscli"}},
            {"name": "dropped",          "unit": "byte",   "value": 3800,  "labels": {"ip_type": "ipv4", "origin": "CAPI"}},
            {"name": "dropped",          "unit": "byte",   "value": 0,     "labels": {"ip_type": "ipv4", "origin": "cscli"}},
            {"name": "dropped",          "unit": "byte",   "value": 1034,  "labels": {"ip_type": "ipv4", "origin": "lists:firehol_cruzit_web_attacks"}},
            {"name": "dropped",          "unit": "byte",   "value": 3847,  "labels": {"ip_type": "ipv4", "origin": "lists:firehol_voipbl"}},
            {"name": "dropped",          "unit": "byte",   "value": 380,   "labels": {"ip_type": "ipv6", "origin": "cscli"}},
            {"name": "dropped",          "unit": "packet", "value": 100,   "labels": {"ip_type": "ipv4", "origin": "CAPI"}},
            {"name": "dropped",          "unit": "packet", "value": 10,    "labels": {"ip_type": "ipv4", "origin": "cscli"}},
            {"name": "dropped",          "unit": "packet", "value": 23,    "labels": {"ip_type": "ipv4", "origin": "lists:firehol_cruzit_web_attacks"}},
            {"name": "dropped",          "unit": "packet", "value": 58,    "labels": {"ip_type": "ipv4", "origin": "lists:firehol_voipbl"}},
            {"name": "dropped",          "unit": "packet", "value": 0,     "labels": {"ip_type": "ipv6", "origin": "cscli"}}
          ]
        }
        ] |
        .remediation_components[0].type = "crowdsec-firewall-bouncer"
    ' <<<"$payload")

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    rune -0 cscli metrics show bouncers -o json
    assert_json '{
    "bouncers": {
     "testbouncer": {
      "": {
       "foo": {
        "dogyear": 2,
        "pound": 5
       }
      },
      "CAPI": {
       "dropped": {
        "byte": 3800,
        "packet": 100
       }
      },
      "cscli": {
       "active_decisions": {
        "ip": 1
       },
       "dropped": {
        "byte": 380,
        "packet": 10
       }
      },
      "lists:firehol_cruzit_web_attacks": {
       "dropped": {
        "byte": 1034,
        "packet": 23
       }
      },
      "lists:firehol_voipbl": {
       "active_decisions": {
        "ip": 51936
       },
       "dropped": {
        "byte": 3847,
        "packet": 58
       }
      }
     }
    }
   }'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	Bouncer Metrics (testbouncer) since 2024-02-08 13:35:16 +0000 UTC:
	+----------------------------------+------------------+-------------------+-----------------+
	| Origin                           | active_decisions |      dropped      |       foo       |
	|                                  |        ip        |   byte  |  packet | dogyear | pound |
	+----------------------------------+------------------+---------+---------+---------+-------+
	|                                  |                0 |       0 |       0 |       2 |     5 |
	| CAPI (community blocklist)       |                0 |   3.80k |     100 |       0 |     0 |
	| cscli                            |                1 |     380 |      10 |       0 |     0 |
	| lists:firehol_cruzit_web_attacks |                0 |   1.03k |      23 |       0 |     0 |
	| lists:firehol_voipbl             |           51.94k |   3.85k |      58 |       0 |     0 |
	+----------------------------------+------------------+---------+---------+---------+-------+
	|                            Total |           51.94k |   9.06k |     191 |       2 |     5 |
	+----------------------------------+------------------+---------+---------+---------+-------+
	EOT

    # TODO: multiple item lists

}

@test "rc usage metrics (multiple bouncers)" {
    # multiple bouncers have separate totals and can have different types of metrics and units -> different columns

    API_KEY=$(cscli bouncers add bouncer1 -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	  - version: "v1.0"
	    utc_startup_timestamp: 1707369316
	    metrics:
	      - meta:
	          utc_now_timestamp: 1707399316
	          window_size_seconds: 600
	        items:
	          - name: dropped
	            unit: byte
	            value: 1000
	            labels:
	              origin: CAPI
	          - name: processed
	            unit: packet
	            value: 100
	            labels:
	              origin: CAPI
	          - name: processed
	            unit: packet
	            value: 100
	            labels:
	              origin: lists:somelist
	EOT
    )

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"

    API_KEY=$(cscli bouncers add bouncer2 -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	  - version: "v1.0"
	    utc_startup_timestamp: 1707379316
	    metrics:
	      - meta:
	          utc_now_timestamp: 1707389316
	          window_size_seconds: 600
	        items:
	          - name: dropped
	            unit: byte
	            value: 1500
	          - name: dropped
	            unit: byte
	            value: 2000
	            labels:
	              origin: CAPI
	          - name: dropped
	            unit: packet
	            value: 20
	EOT
    )

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"

    rune -0 cscli metrics show bouncers -o json
    assert_json '{bouncers:{bouncer1:{CAPI:{dropped:{byte:1000},processed:{packet:100}},"lists:somelist":{processed:{packet:100}}},bouncer2:{"":{dropped:{byte:1500,packet:20}},CAPI:{dropped:{byte:2000}}}}}'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	Bouncer Metrics (bouncer1) since 2024-02-08 13:35:16 +0000 UTC:
	+----------------------------+---------+-----------+
	| Origin                     | dropped | processed |
	|                            |   byte  |   packet  |
	+----------------------------+---------+-----------+
	| CAPI (community blocklist) |   1.00k |       100 |
	| lists:somelist             |       0 |       100 |
	+----------------------------+---------+-----------+
	|                      Total |   1.00k |       200 |
	+----------------------------+---------+-----------+
	
	Bouncer Metrics (bouncer2) since 2024-02-08 10:48:36 +0000 UTC:
	+----------------------------+-------------------+
	| Origin                     |      dropped      |
	|                            |   byte  |  packet |
	+----------------------------+---------+---------+
	|                            |   1.50k |      20 |
	| CAPI (community blocklist) |   2.00k |       0 |
	+----------------------------+---------+---------+
	|                      Total |   3.50k |      20 |
	+----------------------------+---------+---------+
	EOT
}
