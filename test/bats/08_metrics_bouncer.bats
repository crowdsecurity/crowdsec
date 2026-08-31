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

@test "cscli metrics show bouncers (empty)" {
    # this message is given only if we ask explicitly for bouncers
    notfound="No bouncer metrics found."

    rune -0 cscli metrics show bouncers
    assert_output "$notfound"

    rune -0 cscli metrics list
    refute_output "$notfound"
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
    assert_json '{message: "json: cannot unmarshal string into Go struct field AllMetrics.remediation_components.utc_startup_timestamp of type int64"}'

    payload=$(yq -o j '.remediation_components[0].utc_startup_timestamp = 1707399316' <<<"$payload")
    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    refute_output

    payload=$(yq -o j '.remediation_components[0].metrics = [{"meta": {}}]' <<<"$payload")
    rune -22 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"
    assert_stderr --partial "error: 422"
    rune -0 jq -r '.message' <(output)
    assert_output - <<-EOT
	validation failure list:
	remediation_components.0.metrics.0.items in body is required
	EOT
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
    assert_json '{bouncers:{testbouncer:{"": {foo: {dogyear: 2, pound: 5}}}}}'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+--------------------------+
	| Bouncer Metrics (testbou |
	| ncer) since 2024-02-08 1 |
	| 3:35:16 +0000 UTC        |
	+--------+-----------------+
	| Origin |       foo       |
	|        | dogyear | pound |
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
            {"name": "active_decisions", "unit": "ip",     "value": 500,   "labels": {"ip_type": "ipv4", "origin": "lists:firehol_voipbl"}},
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
            {"name": "dropped",          "unit": "packet", "value": 0,     "labels": {"ip_type": "ipv4", "origin": "lists:anotherlist"}},
            {"name": "dropped",          "unit": "byte",   "value": 0,     "labels": {"ip_type": "ipv4", "origin": "lists:anotherlist"}},
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
            "ip": 500
          },
          "dropped": {
            "byte": 3847,
            "packet": 58
          },
        },
        "lists:anotherlist": {
          "dropped": {
            "byte": 0,
            "packet": 0
          }
        }
      }
    }
   }'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+-----------------------------------------------------------------------------------------+
	| Bouncer Metrics (testbouncer) since 2024-02-08 13:35:16 +0000 UTC                       |
	+----------------------------------+------------------+-----------------+-----------------+
	| Origin                           | active_decisions |     dropped     |       foo       |
	|                                  |        IPs       | bytes | packets | dogyear | pound |
	+----------------------------------+------------------+-------+---------+---------+-------+
	| CAPI (community blocklist)       |                - | 3.80k |     100 |       - |     - |
	| cscli (manual decisions)         |                1 |   380 |      10 |       - |     - |
	| lists:anotherlist                |                - |     0 |       0 |       - |     - |
	| lists:firehol_cruzit_web_attacks |                - | 1.03k |      23 |       - |     - |
	| lists:firehol_voipbl             |              500 | 3.85k |      58 |       - |     - |
	+----------------------------------+------------------+-------+---------+---------+-------+
	|                            Total |              501 | 9.06k |     191 |       2 |     5 |
	+----------------------------------+------------------+-------+---------+---------+-------+
	EOT

    # active_decisions is actually a gauge: values should not be aggregated, keep only the latest one

    payload=$(yq -o j '
        .remediation_components[0].metrics = [
        {
          "meta": {"utc_now_timestamp": 1707450000, "window_size_seconds":600},
          "items":[
            {"name": "active_decisions", "unit": "ip",     "value": 250, "labels": {"ip_type": "ipv4", "origin": "lists:firehol_voipbl"}},
            {"name": "active_decisions", "unit": "ip",     "value": 10,  "labels": {"ip_type": "ipv6", "origin": "cscli"}}
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
            "ip": 10
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
            "ip": 250
          },
          "dropped": {
            "byte": 3847,
            "packet": 58
          },
        },
        "lists:anotherlist": {
          "dropped": {
            "byte": 0,
            "packet": 0
          }
        }
      }
    }
   }'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+-----------------------------------------------------------------------------------------+
	| Bouncer Metrics (testbouncer) since 2024-02-08 13:35:16 +0000 UTC                       |
	+----------------------------------+------------------+-----------------+-----------------+
	| Origin                           | active_decisions |     dropped     |       foo       |
	|                                  |        IPs       | bytes | packets | dogyear | pound |
	+----------------------------------+------------------+-------+---------+---------+-------+
	| CAPI (community blocklist)       |                - | 3.80k |     100 |       - |     - |
	| cscli (manual decisions)         |               10 |   380 |      10 |       - |     - |
	| lists:anotherlist                |                - |     0 |       0 |       - |     - |
	| lists:firehol_cruzit_web_attacks |                - | 1.03k |      23 |       - |     - |
	| lists:firehol_voipbl             |              250 | 3.85k |      58 |       - |     - |
	+----------------------------------+------------------+-------+---------+---------+-------+
	|                            Total |              260 | 9.06k |     191 |       2 |     5 |
	+----------------------------------+------------------+-------+---------+---------+-------+
	EOT
}

@test "rc usage metrics (unknown metrics)" {
    # new metrics are introduced in a new bouncer version, unknown by this version of cscli: some are gauges, some are not

    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	  - version: "v1.0"
	    utc_startup_timestamp: 1707369316
	log_processors: []
	EOT
    )

    payload=$(yq -o j '
        .remediation_components[0].metrics = [
        {
          "meta": {"utc_now_timestamp": 1707460000, "window_size_seconds":600},
          "items":[
            {"name": "ima_gauge", "unit": "second", "value": 30, "labels": {"origin": "cscli"}},
            {"name": "notagauge", "unit": "inch",   "value": 15, "labels": {"origin": "cscli"}}
          ]
        }, {
          "meta": {"utc_now_timestamp": 1707450000, "window_size_seconds":600},
          "items":[
            {"name": "ima_gauge", "unit": "second", "value": 20, "labels": {"origin": "cscli"}},
            {"name": "notagauge", "unit": "inch",   "value": 10, "labels": {"origin": "cscli"}}
          ]
        }
        ] |
        .remediation_components[0].type = "crowdsec-firewall-bouncer"
    ' <<<"$payload")

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"

    rune -0 cscli metrics show bouncers -o json
    assert_json '{bouncers: {testbouncer: {cscli: {ima_gauge: {second: 30}, notagauge: {inch: 25}}}}}'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+-----------------------------------------------+
	| Bouncer Metrics (testbouncer) since 2024-02-0 |
	| 9 03:40:00 +0000 UTC                          |
	+--------------------------+--------+-----------+
	| Origin                   |   ima  | notagauge |
	|                          | second |    inch   |
	+--------------------------+--------+-----------+
	| cscli (manual decisions) |     30 |        25 |
	+--------------------------+--------+-----------+
	|                    Total |     30 |        25 |
	+--------------------------+--------+-----------+
	EOT
}

@test "rc usage metrics (ipv4/ipv6)" {
    # gauge metrics are not aggregated over time, but they are over ip type

    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY

    payload=$(yq -o j <<-EOT
	remediation_components:
	  - version: "v1.0"
	    utc_startup_timestamp: 1707369316
	log_processors: []
	EOT
    )

    payload=$(yq -o j '
        .remediation_components[0].metrics = [
        {
          "meta": {"utc_now_timestamp": 1707460000, "window_size_seconds":600},
          "items":[
            {"name": "active_decisions", "unit": "ip", "value": 200, "labels": {"ip_type": "ipv4", "origin": "cscli"}},
            {"name": "active_decisions", "unit": "ip", "value": 30,  "labels": {"ip_type": "ipv6", "origin": "cscli"}}
          ]
        }, {
          "meta": {"utc_now_timestamp": 1707450000, "window_size_seconds":600},
          "items":[
            {"name": "active_decisions", "unit": "ip", "value": 400, "labels": {"ip_type": "ipv4", "origin": "cscli"}},
            {"name": "active_decisions", "unit": "ip", "value": 50,  "labels": {"ip_type": "ipv6", "origin": "cscli"}}
          ]
        }
        ] |
        .remediation_components[0].type = "crowdsec-firewall-bouncer"
    ' <<<"$payload")

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"

    rune -0 cscli metrics show bouncers -o json
    assert_json '{bouncers: {testbouncer: {cscli: {active_decisions: {ip: 230}}}}}'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+---------------------------------------------+
	| Bouncer Metrics (testbouncer) since 2024-02 |
	| -09 03:40:00 +0000 UTC                      |
	+--------------------------+------------------+
	| Origin                   | active_decisions |
	|                          |        IPs       |
	+--------------------------+------------------+
	| cscli (manual decisions) |              230 |
	+--------------------------+------------------+
	|                    Total |              230 |
	+--------------------------+------------------+
	EOT
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
	          - name: dropped
	            unit: byte
	            value: 800
	            labels:
	              origin: lists:somelist
	          - name: processed
	            unit: byte
	            value: 12340
	          - name: processed
	            unit: packet
	            value: 100
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
	            labels:
	              origin: lists:somelist
	          - name: dropped
	            unit: byte
	            value: 2000
	            labels:
	              origin: CAPI
	          - name: dropped
	            unit: packet
	            value: 20
	            labels:
	              origin: lists:somelist
	EOT
    )

    rune -0 curl-with-key '/v1/usage-metrics' -X POST --data "$payload"

    rune -0 cscli metrics show bouncers -o json
    assert_json '{bouncers:{bouncer1:{"":{processed:{byte:12340,packet:100}},CAPI:{dropped:{byte:1000}},"lists:somelist":{dropped:{byte:800}}},bouncer2:{"lists:somelist":{dropped:{byte:1500,packet:20}},CAPI:{dropped:{byte:2000}}}}}'

    rune -0 cscli metrics show bouncers
    assert_output - <<-EOT
	+---------------------------------------------------------+
	| Bouncer Metrics (bouncer1) since 2024-02-08 13:35:16 +0 |
	| 000 UTC                                                 |
	+----------------------------+---------+------------------+
	| Origin                     | dropped |     processed    |
	|                            |  bytes  |  bytes | packets |
	+----------------------------+---------+--------+---------+
	| CAPI (community blocklist) |   1.00k |      - |       - |
	| lists:somelist             |     800 |      - |       - |
	+----------------------------+---------+--------+---------+
	|                      Total |   1.80k | 12.34k |     100 |
	+----------------------------+---------+--------+---------+
	+----------------------------------------------+
	| Bouncer Metrics (bouncer2) since 2024-02-08  |
	| 10:48:36 +0000 UTC                           |
	+----------------------------+-----------------+
	| Origin                     |     dropped     |
	|                            | bytes | packets |
	+----------------------------+-------+---------+
	| CAPI (community blocklist) | 2.00k |       - |
	| lists:somelist             | 1.50k |      20 |
	+----------------------------+-------+---------+
	|                      Total | 3.50k |      20 |
	+----------------------------+-------+---------+
	EOT
}
