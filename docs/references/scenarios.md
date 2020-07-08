## Understanding scenarios


Scenarios are YAML files that allow to detect and qualify a specific behavior, usually an attack.

Scenarios receive one or more {{event.htmlname}} and might produce one or more {{overflow.htmlname}}.
As an {{event.htmlname}} can be the representation of a log line, or an overflow, it  allows scenarios to process both logs or overflows.


The scenario is usually based on a number of factors, at least :

  - the speed/frequency at which events happen (see [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket))
  - the characteristic(s) of an  {{event.htmlname}} : "log type XX with field YY set to ZZ"



Behind the scenes, {{crowdsec.name}} is going to create one or several buckets when event with matching characteristic arrive to the scenario. This bucket has a capacity and leak-speed, when the bucket "overflows", the scenario has been trigger.

_Bucket partitioning_ : One scenario usually leads to many bucket creation, as each bucket is only tracking a specific subset of events. For example, if we are tracking brute-force, it makes sense that each "offending peer" get its own bucket.


A way to detect a http scanner might be to track the number of distinct non-existing pages it's requesting, and the scenario might look like this :


```yaml
#the bucket type : leaky, trigger, counter
type: leaky
#name and description for humans
name: crowdsecurity/http-scan-uniques_404
description: "Detect multiple unique 404 from a single ip"
#a filter to know which events are eligible
filter: "evt.Meta.service == 'http' && evt.Meta.http_status in ['404', '403', '400']"
#how we are going to partition buckets
groupby: "evt.Meta.source_ip"
#we are only interested into counting UNIQUE/DISTINCT requested URLs
distinct: "evt.Meta.http_path"
#we specify the bucket capacity and leak speed
capacity: 5
leakspeed: "10s"
#this will prevent the same bucket from overflowing more often than every 5 minutes
blackhole: 5m
#some labels to give context to the overflow
labels:
 service: http
 type: scan
 #yes we want to ban people triggering this
 remediation: true
```


## Scenario concepts

### TimeMachine

{{crowdsec.name}} can be used not only to process live logs, but as well to process "cold" logs (think forensics).

For this to be able to work, the date/time from the log must have been properly parsed for the scenario temporal aspect to be able to work properly. This relies on the [dateparser enrichment](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/dateparse-enrich.yaml)


## Scenario directives

### type


```yaml
type: leaky|trigger|counter
```

Defines the type of the bucket. Currently three types are supported :

 - `leaky` : a [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket) that must be configured with a {{capacity.htmlname}} and a {{leakspeed.htmlname}}
 - `trigger` : a bucket that overflows as soon as an event is poured (it's like a leaky bucket is a capacity of 0)
 - `counter` : a bucket that only overflows every {{duration.htmlname}}. It's especially useful to count things.

### name & description

```yaml
name: my_author_name/my_scenario_name
description: A scenario that detect XXXX behavior
```


Mandatory `name` and `description` for said scenario. 
The name must be unique (and will define the scenario's name in the hub), and the description must be a quick sentence describing what it detects.


### filter

```yaml
filter: expression
```

`filter` must be a valid {{expr.htmlname}} expression that will be evaluated against the {{event.htmlname}}.

If `filter` evaluation returns true or is absent, event will be pour in the bucket.

If `filter` returns `false` or a non-boolean, the event will be skip for this bucket.

Here is the [expr documentation](https://github.com/antonmedv/expr/tree/master/docs).

Examples :

  - `evt.Meta.log_type == 'telnet_new_session'`
  - `evt.Meta.log_type in ['http_access-log', 'http_error-log'] && evt.Parsed.static_ressource == 'false'`
  - `evt.Meta.log_type == 'ssh_failed-auth'`


### duration

```yaml
duration: 45s
duration: 10m
```

(applicable to `counter` buckets only)

A duration after which the bucket will overflow.
The format must be compatible with [golang ParseDuration format](https://golang.org/pkg/time/#ParseDuration)

Examples :

```yaml
type: counter
name: crowdsecurity/ban-reports-ssh_bf_report
description: "Count unique ips performing ssh bruteforce"
filter: "evt.Overflow.Scenario == 'ssh_bruteforce'"
distinct: "evt.Overflow.Source_ip"
capacity: -1
duration: 10m
labels:
  service: ssh
```


### groupby

```yaml
groupby: evt.Meta.source_ip
```


an {{expr.htmlname}} that must return a string. This string will be used as to partition the buckets.


Examples :

Here, each `source_ip` will get its own bucket.

```yaml
type: leaky
...
groupby: evt.Meta.source_ip
...
```



Here, each unique combo of `source_ip` + `target_username` will get its own bucket.

```yaml
type: leaky
...
groupby: evt.Meta.source_ip + '--' + evt.Parsed.target_username
...
```



### distinct


```yaml
distinct: evt.Meta.http_path
```


an {{expr.htmlname}} that must return a string. The event will be poured **only** if the string is not already present in the bucket.

Examples :

This will ensure that events that keep triggering the same `.Meta.http_path` will be poured only once.

```yaml
type: leaky
...
distinct: "evt.Meta.http_path"
...
```

In the logs, you can see it like this (for example from the iptables-logs portscan detection) :

```bash
DEBU[2020-05-13T11:29:51+02:00] Uniq(7681) : ok                               buck..
DEBU[2020-05-13T11:29:51+02:00] Uniq(7681) : ko, discard event                buck..
```

The first event has been poured (value `7681`) was not yet present in the events, while the second time, the event got discarded because the value was already present in the bucket.


### capacity

```yaml
capacity: 5
```


(Applies only to `leaky` buckets)

A positive integer representing the bucket capacity.
If there are more than `capacity` item in the bucket, it will overflow.


### leakspeed

```yaml
leakspeed: "10s"
```

(Applies only to `leaky` buckets)

A duration that represent how often an event will be leaking from the bucket.

Must be compatible with [golang ParseDuration format](https://golang.org/pkg/time/#ParseDuration).


Example:

Here the bucket will leak one item every 10 seconds, and can hold up to 5 items before overflowing.

```yaml
type: leaky
...
leakspeed: "10s"
capacity: 5
...
```


### labels

```yaml
labels:
 service: ssh
 type: bruteforce
 remediation: true
```

Labels is a list of `label: values` that provide context to an overflow.
The labels are (currently) not stored in the database, nor they are sent to the API.

Special labels :

 - The **remediation** label, if set to `true` indicate the the originating IP should be ban.
 - The **scope** label, can be set to `ip` or `range` when **remediation** is set to true, and indicate to which scope should the decision apply. If you set a scenario with **remediation** to true and **scope** to `range` and the range of the IP could have been determined by the GeoIP library, the whole range to which the IP belongs will be banned.


Example :

The IP that triggered the overflow (`.Meta.source_ip`) will be banned.
```yaml
type: leaky
...
labels:
 service: ssh
 type: bruteforce
 remediation: true
```

The range to which the offending IP belong (`.Meta.source_ip`) will be banned.
```yaml
type: leaky
...
labels:
 type: distributed_attack
 remediation: true
 scope: range
```

### blackhole

```yaml
blackhole: 10m
```

A duration for which a bucket will be "silenced" after overflowing.
This is intended to limit / avoid spam of buckets that might be very rapidly triggered.

The blackhole only applies to the individual bucket rather than the whole scenario.

Must be compatible with [golang ParseDuration format](https://golang.org/pkg/time/#ParseDuration).

Example :

The same `source_ip` won't be able to trigger this overflow more than once every 10 minutes.
The potential overflows in the meanwhile will be discarded (but will still appear in logs as being blackholed).

```yaml
type: trigger
...
blackhole: 10m
groupby: evt.Meta.source_ip
```

### debug

```yaml
debug: true|false
```

_default: false_


If set to to `true`, enabled scenario level debugging.
It is meant to help understanding scenario  behavior by providing contextual logging.

### reprocess

```yaml
reprocess: true|false
```

_default: false_

If set to `true`, the resulting overflow will be sent again in the scenario/parsing pipeline.
It is useful when you want to have further scenarios that will rely on past-overflows to take decisions.


### cache_size

```yaml
cache_size: 5
```

By default, a bucket holds {{capacity.htmlname}} events "in memory".
However, for a number of cases, you don't want this, as it might lead to excessive memory consumption.

By setting `cache_size` to a positive integer, we can control the maximum in-memory cache size of the bucket, without changing its capacity and such. This is especially useful when using `counter` buckets on long duration that might end up counting (and this storing in memory) an important number of events.


### overflow_filter

```yaml
overflow_filter: any(queue.Queue, { .Enriched.IsInEU  == "true" })
```

`overflow_filter` is an {{expr.htmlname}} that is run when the bucket overflows.
If this expression is present and returns false, the overflow will be discarded.


### data

```
data:
  - source_url: https://URL/TO/FILE
    dest_file: LOCAL_FILENAME
```

`data` allows user to specify an external source of data.
This section is only relevant when `cscli` is used to install scenario from hub, as ill download the `source_url` and store it to `dest_file`. When the scenario is not from the hub, this part has no impact.


```yaml
name: crowdsecurity/cdn-whitelist
...
data:
  - source_url: https://www.cloudflare.com/ips-v4
    dest_file: cloudflare_ips.txt
```


