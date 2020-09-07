# Writing {{crowdsec.Name}} scenarios

!!! info
    Please ensure that you have working env or setup test environment before writing your scenario.

    Ensure that your logs are properly parsed.

    Have some sample logs at hand reach to test your scenario as you progress.


> In the current example, we'll write a scenario to detect port scans relying on the logs produced by `iptables` (netfilter) with the `-j LOG` target.

> This document aims at detailing the process of writing and testing new scenarios.


## Base scenario file


The simple scenario can be defined as :

```yaml
type: leaky
debug: true
name: me/my-cool-scenario
description: "detect cool stuff"
filter: "1 == 1"
capacity: 1
leakspeed: 1m
blackhole: 1m
labels:
  type: my_test
```

 - a {{filter.htmlname}} : if the expression is `true`, the event will enter the parser, otherwise, it won't
 - a name & a description
 - a capacity for our [Leaky Bucket](https://en.wikipedia.org/wiki/Leaky_bucket)
 - a leak speed for our  [Leaky Bucket](https://en.wikipedia.org/wiki/Leaky_bucket)
 - a blackhole duration (it will prevent the same bucket from overflowing too often to limit spam)
 - some labels to qualify the events that just happen
 - a `debug` flag that allows to enable local debugging information.


We are going to use the following sample log in our example :

```bash
May 12 09:40:15 sd-126005 kernel: [47678084.929208] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=66.66.66.66 DST=127.0.0.1 LEN=40 TOS=0x08 PREC=0x20 TTL=244 ID=54321 PROTO=TCP SPT=42403 DPT=7681 WINDOW=65535 RES=0x00 SYN URGP=0 
May 12 09:40:15 sd-126005 kernel: [47678084.929245] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=99.99.99.99 DST=127.0.0.1 LEN=40 TOS=0x08 PREC=0x20 TTL=244 ID=54321 PROTO=TCP SPT=42403 DPT=7681 WINDOW=65535 RES=0x00 SYN URGP=0 
May 12 09:40:16 sd-126005 kernel: [47678084.929208] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=99.99.99.99 DST=127.0.0.1 LEN=40 TOS=0x08 PREC=0x20 TTL=244 ID=54321 PROTO=TCP SPT=42403 DPT=7681 WINDOW=65535 RES=0x00 SYN URGP=0
May 12 09:40:16 sd-126005 kernel: [47678084.929208] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=44.44.44.44 DST=127.0.0.1 LEN=40 TOS=0x08 PREC=0x20 TTL=244 ID=54321 PROTO=TCP SPT=42403 DPT=7681 WINDOW=65535 RES=0x00 SYN URGP=0 
```

## Let's try our mock scenario

!!! info
    This assumes that you've followed the previous tutorial and that your iptables logs are properly parsed


```bash
./crowdsec -c ./dev.yaml -file ./x.log -type syslog
```


<details>
  <summary>Expected output</summary>
```bash
...
DEBU[2020-05-12T11:22:17+02:00] eval(TRUE) 1 == 1                             cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:22:17+02:00] Instanciating TimeMachine bucket              cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:22:17+02:00] Leaky routine starting, lifetime : 2m0s       bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] Pouring event                                 bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] First pour, creation timestamp : 2020-05-12 09:40:15 +0000 UTC  bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] eval(TRUE) 1 == 1                             cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:22:17+02:00] Pouring event                                 bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] Bucket overflow at 2020-05-12 09:40:15 +0000 UTC  bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] Overflow, bucket start: 2020-05-12 09:40:15 +0000 UTC, bucket end : 2020-05-12 09:40:15 +0000 UTC  bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] Adding blackhole (until: 2020-05-12 09:41:15 +0000 UTC)  bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] Leaky routine exit                            bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
DEBU[2020-05-12T11:22:17+02:00] eval(TRUE) 1 == 1                             cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario
INFO[12-05-2020 11:22:17] node warning : no remediation                 bucket_id=withered-brook event_time="2020-05-12 09:40:15 +0000 UTC" scenario=me/my-cool-scenario source_ip=66.66.66.66
DEBU[2020-05-12T11:22:17+02:00] Bucket f16d5033bebe7090fb626f5feb4e4073cee206d4 dead/expired, cleanup  bucket_id=withered-brook capacity=1 cfg=snowy-dawn file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=f16d5033bebe7090fb626f5feb4e4073cee206d4
INFO[12-05-2020 11:22:17] Processing Overflow with no decisions 2 IPs performed 'me/my-cool-scenario' (2 events over 0s) at 2020-05-12 09:40:15 +0000 UTC  bucket_id=withered-brook event_time="2020-05-12 09:40:15 +0000 UTC" scenario=me/my-cool-scenario source_ip=66.66.66.66
...  
```
</details>


We can see our "mock" scenario is working, let's see what happened :

- The first event (parsed line) is processed :

    - The `filter` returned true (`1 == 1`) so the {{event.htmlname}} will be processed by our bucket
    - The bucket is instantiated in {{timeMachine.htmlname}} mode, and its creation date is set to the timestamp from the first log
    - The {{event.htmlname}} is poured in the actual bucket

- The second event is processed
    - The `filter` is still true, and the event is poured
    - As our bucket's capacity is `1`, pouring this second overflow leads to an {{overflow.htmlname}}
    - Because we set a blackhole directive of `1 minute`, we remember to prevent this bucket to overflowing again for the next minute

The overflow itself is produced and we get this message :

```
INFO[12-05-2020 11:22:17] Processing Overflow with no decisions 2 IPs performed 'me/my-cool-scenario' (2 events over 0s) at 2020-05-12 09:40:15 +0000 UTC  bucket_id=withered-brook event_time="2020-05-12 09:40:15 +0000 UTC" scenario=me/my-cool-scenario source_ip=66.66.66.66

```

!!! warning
    While it "worked" we can see the first issue : the offending IP is reported to be `66.66.66.66` but there are actually 3 IPs involved (`66.66.66.66`, `99.99.99.99` and `44.44.44.44`). To make sense our "detect port scans" should detect events coming from a single IP !


## One step forward : peer attribution

Let's evolve our scenario to be closer to something meaningful :


```yaml
type: leaky
debug: true
name: me/my-cool-scenario
description: "detect cool stuff"
filter: "evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'"
groupby: evt.Meta.source_ip
capacity: 1
leakspeed: 1m
blackhole: 1m
labels:
  type: my_test
```

What did we change ?

 - we added a meaningful filter : we are only going to look into `iptables_drop` events, and only take care of `tcp` ones (see the parser we wrote in the [previous step](/write_configurations/parsers/))
 - we added a `groupby` directive : it's going to ensure that each offending peer get its own bucket


Let's try again !

```bash
./crowdsec -c ./dev.yaml -file ./x.log -type syslog
```

<details>
  <summary>Expected output</summary>
```bash
...
DEBU[2020-05-12T11:25:20+02:00] eval(TRUE) evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'  cfg=holy-breeze file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:25:20+02:00] Leaky routine starting, lifetime : 2m0s       bucket_id=cold-lake capacity=1 cfg=holy-breeze file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=2308799e2cc5b57331df10eb93a495aff7725922
...
DEBU[2020-05-12T11:25:20+02:00] eval(TRUE) evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'  cfg=holy-breeze file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:25:20+02:00] Instanciating TimeMachine bucket              cfg=holy-breeze file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:25:20+02:00] Leaky routine starting, lifetime : 2m0s       bucket_id=muddy-haze capacity=1 cfg=holy-breeze file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=6236f134d0f34d0061748c065bdcb64d8ac6dc54
...
INFO[12-05-2020 11:25:20] node warning : no remediation                 bucket_id=muddy-haze event_time="2020-05-12 09:40:16 +0000 UTC" scenario=me/my-cool-scenario source_ip=99.99.99.99
INFO[12-05-2020 11:25:20] Processing Overflow with no decisions 99.99.99.99 performed 'me/my-cool-scenario' (2 events over 1s) at 2020-05-12 09:40:16 +0000 UTC  bucket_id=muddy-haze event_time="2020-05-12 09:40:16 +0000 UTC" scenario=me/my-cool-scenario source_ip=99.99.99.99
...

```
</details>

Let's see what happened :

  - Thanks to our `groupby` key, we now see two different partition keys appearing (`partition=...`).
    It means that each peer will get its own bucket, and a "unique key" is derived from the groupby field value (here : the source IP)

  - We see that we only have one overflow, and it correctly concerns  `99.99.99.99` (it's the one that actually triggered two events). This is again thanks to the groupby key
  

## One step forward : unique ports



Is it done ? not yet, but we're getting close !

To really qualify a port-scan, we want to rely on the number of unique probed ports. Let's arbitrarily decide that a port-scan is : "One peer trying to probe AT LEAST 15 different ports within a few seconds"

Our evolved scenario is now :

```yaml
type: leaky
debug: true
name: me/my-cool-scenario
description: "detect cool stuff"
filter: "evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'"
groupby: evt.Meta.source_ip
distinct: evt.Parsed.dst_port
capacity: 15
leakspeed: 5s
blackhole: 1m
labels:
  type: scan
  service: tcp

```

What did we changed :

 - We add a `distinct` directive on the `evt.Parsed.dst_port`. It allows the bucket to discard any event with an already seen `evt.Parsed.dst_port`. (yes, like in SQL)
 - We changed `capacity` and `leakspeed` to be more relevant to our target
 - We fixed the `labels` so that the event makes sense !


Let's see what it changes :

```bash
./crowdsec -c ./dev.yaml -file ./x.log -type syslog
```

<details>
  <summary>Expected output</summary>
```bash
...
DEBU[2020-05-12T11:49:01+02:00] eval(TRUE) evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'  cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:49:01+02:00] Instantiating TimeMachine bucket              cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario
DEBU[2020-05-12T11:49:01+02:00] Leaky routine starting, lifetime : 1m20s      bucket_id=nameless-feather capacity=15 cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=2308799e2cc5b57331df10eb93a495aff7725922
DEBU[2020-05-12T11:49:01+02:00] Uniq 'evt.Parsed.dst_port' -> '7681'          bucket_id=nameless-feather capacity=15 cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=2308799e2cc5b57331df10eb93a495aff7725922
DEBU[2020-05-12T11:49:01+02:00] Uniq(7681) : false, discard                   bucket_id=nameless-feather capacity=15 cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=2308799e2cc5b57331df10eb93a495aff7725922
DEBU[2020-05-12T11:49:01+02:00] Pouring event                                 bucket_id=nameless-feather capacity=15 cfg=dark-pond file=config/scenarios/mytest.yaml name=me/my-cool-scenario partition=2308799e2cc5b57331df10eb93a495aff7725922
...

```
</details>

 - We can see that the second event was discarded, because it had a destination port similar to the first one
 - No overflow were produced

 
## Is it really working

Ok, **fingers crossed** our thing should be working.

Let's grab some real-life logs !

```bash
$ wc -l kern.log 
78215 kern.log
$ head -n1 kern.log
May 11 06:25:20 sd-126005 kernel: ... 
$ tail -n1 kern.log
May 12 12:09:00 sd-126005 kernel: ... 
```

We have around 80k lines averaging about 24h of logs, let's try !

```bash
./crowdsec -c ./dev.yaml -file ./kern.log -type syslog 
```

<details>
  <summary>Expected output</summary>
```bash
INFO[0000] setting loglevel to info                     
INFO[12-05-2020 11:50:38] Crowdsec v0.0.18-f672dbb4aec29ca2b24080a33d4d92eb9d4441cc 
...
INFO[12-05-2020 11:50:42] node warning : no remediation                 bucket_id=sparkling-violet event_time="2020-05-11 10:41:45 +0000 UTC" scenario=me/my-cool-scenario source_ip=xx.xx.xx.xx
INFO[12-05-2020 11:50:42] Processing Overflow with no decisions xx.xx.xx.xx performed 'me/my-cool-scenario' (16 events over 0s) at 2020-05-11 10:41:45 +0000 UTC  bucket_id=sparkling-violet event_time="2020-05-11 10:41:45 +0000 UTC" scenario=me/my-cool-scenario source_ip=xx.xx.xx.xx
...
INFO[12-05-2020 11:50:43] node warning : no remediation                 bucket_id=quiet-leaf event_time="2020-05-11 11:34:11 +0000 UTC" scenario=me/my-cool-scenario source_ip=yy.yy.yy.yy
INFO[12-05-2020 11:50:43] Processing Overflow with no decisions yy.yy.yy.yy performed 'me/my-cool-scenario' (16 events over 2s) at 2020-05-11 11:34:11 +0000 UTC  bucket_id=quiet-leaf event_time="2020-05-11 11:34:11 +0000 UTC" scenario=me/my-cool-scenario source_ip=yy.yy.yy.yy
...
WARN[12-05-2020 11:51:05] read 78215 lines                              file=./kern.log
...
```
</details>

It seems to work correctly !


## Hold my beer and watch this


One I have acquire confidence in my scenario and I want it to trigger some bans, we can simply add :


```yaml
type: leaky
debug: true
name: me/my-cool-scenario
description: "detect cool stuff"
filter: "evt.Meta.log_type == 'iptables_drop' && evt.Meta.service == 'tcp'"
groupby: evt.Meta.source_ip
distinct: evt.Parsed.dst_port
capacity: 15
leakspeed: 5s
blackhole: 1m
labels:
  type: scan
  service: tcp
  remediation: true
  scope: ip
```


Adding `remediation: true` into the labels tells {{crowdsec.name}} that we should write a ban for the IP when the scenario is triggered ! 

Let's try :

 - I copied the yaml file to a production system (`/etc/crowdsec/crowdsec/scenarios/mytest.yaml`)
 - I restart {{crowdsec.name}} (`systemctl restart crowdsec`)

Let's check if it seems correctly enabled :

```bash
$ {{cli.bin}} list
...
INFO[0000] SCENARIOS:                                   
----------------------------------------------------------------------------------------------------------------------------------
 NAME                                  📦 STATUS          VERSION  LOCAL PATH                                                     
----------------------------------------------------------------------------------------------------------------------------------
...
 mytest.yaml                           🚫  enabled,local           /etc/crowdsec/config/scenarios/mytest.yaml                 
...
```


Let's launch (from an external machine, as {{crowdsec.name}} ignores events from private IPs by default) a real port-scan with a good old `nmap` :

```bash
sudo nmap -sS xx.xx.xx.xx
```


and on our server :

```bash
$ tail -f /var/log/crowdsec.log 
...
time="12-05-2020 12:31:43" level=warning msg="xx.xx.16.6 triggered a 4h0m0s ip ban remediation for [me/my-cool-scenario]" bucket_id=wispy-breeze event_time="2020-05-12 12:31:43.953498645 +0200 CEST m=+64.533521568" scenario=me/my-cool-scenario source_ip=xx.xx.16.6
...
^C
$ {{cli.bin}}  ban list
INFO[0000] backend plugin 'sqlite' loaded               
8 local decisions:
+--------+-----------------+----------------------+------+--------+---------+--------------------------+--------+------------+
| SOURCE |       IP        |        REASON        | BANS | ACTION | COUNTRY |            AS            | EVENTS | EXPIRATION |
+--------+-----------------+----------------------+------+--------+---------+--------------------------+--------+------------+
| local  | xx.xx.xx.xx     | me/my-cool-scenario  |    4 | ban    | FR      | 21502 SFR SA             |     79 | 3h58m27s   |
...
```

It worked !!!




<!-- 






# Writing Crowdsec scenario

> Please refer to []() if the parser doesn't exist

## Acquiring the logs

First step to test a scenario is to get the logs that trigger your wanted scenario.

## Write the yaml configuration file
 
The first configuration for a scenario is the [type]().
It can uniq, trigger or leaky. Please [see here]() for more description about scenarios type.

```yaml
type: leaky
```

Then the `name`. Please write it in the form of `<github_account_name>/<scenario_name>` .

```yaml
name: crowdsecurity/http-scan-uniques_404
```

Describe in one sentence what this scenario trigger :

```yaml
description: Detect multiple unique 404 from a single ip
```

Now come the filter, the one that will decide if the incoming log will be store in our bucket.
For the HTTP 404 scans, we want only logs from web request that return a `404`, `403` or `400` HTTP code:

```yaml
filter: "evt.Meta.service == 'http' && evt.Meta.http_status in ['404', '403', '400']"
```

Then we want to groupby this scenario for `source_ip` (ip of the attacker) :
```yaml
groupby: evt.Meta.source_ip
```

And we want only one log to be store for each HTTP URI query by the attacker (no duplicate):
```yaml
distinct: evt.Meta.http_path
```

We can say that if someone query 5 or more unknown or forbidden HTTP URI with a leakspeed of 10s, then it is probably a web scan:
```yaml
capacity: 5
leakspeed: "10s"
```

Then we want to blackhole it for 5minutes (because if the attacker crawl a lot, we don't want to be notofied for every 5 times HTTP 404/403/400):
```yaml
blackhole: 5m
```

We also want to reprocess this scenarios if it happen for more heuristic:
```yaml
reprocess: true
```

And then we give some labels to this scenario for remediation:
```yaml
service: http
type: scan
remediation: true
```

Full example scenario:

<details>
<summary>Nginx </summary>

```yaml
# 404 scan
type: leaky
#debug: true
name: crowdsecurity/http-scan-uniques_404
description: "Detect multiple unique 404 from a single ip"
filter: "evt.Meta.service == 'http' && evt.Meta.http_status in ['404', '403', '400']"
groupby: "evt.Meta.source_ip"
distinct: "evt.Meta.http_path"
capacity: 5
#debug: true
reprocess: true
leakspeed: "10s"
blackhole: 5m
labels:
 service: http
 type: scan
 remediation: true
```
</details> -->