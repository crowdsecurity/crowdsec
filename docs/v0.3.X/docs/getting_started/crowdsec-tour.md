
## List installed configurations

> List installed parsers/scenarios/collections/enricher

```bash
{{v0X.cli.bin}} list
```

On the machine where you deployed {{v0X.crowdsec.name}}, type `{{v0X.cli.bin}} list` to see deployed configurations.
This list represents the parsers, scenarios and/or collections that you deployed. They represent what your {{v0X.crowdsec.name}} setup can read (logs) and detect (scenarios).

Check [{{v0X.cli.name}} configuration](/Crowdsec/v0/guide/cscli/) management for more !

<details>
  <summary>output example</summary>
```bash
bui@sd:~$ {{v0X.cli.bin}}  list
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
INFO[0000] PARSERS:                                     
--------------------------------------------------------------------------------------------------------------------
 NAME                       📦 STATUS    VERSION  LOCAL PATH                                                        
--------------------------------------------------------------------------------------------------------------------
 crowdsec/nginx-logs        ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/nginx-logs.yaml        
 crowdsec/sshd-logs         ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/sshd-logs.yaml         
 crowdsec/syslog-logs       ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml         
 crowdsec/whitelists        ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/whitelists.yaml       
 crowdsec/dateparse-enrich  ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/dateparse-enrich.yaml 
 crowdsec/iptables-logs     ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/iptables-logs.yaml     
 crowdsec/naxsi-logs        ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/naxsi-logs.yaml       
 crowdsec/http-logs         ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/http-logs.yaml        
 crowdsec/geoip-enrich      ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/geoip-enrich.yaml     
--------------------------------------------------------------------------------------------------------------------
INFO[0000] SCENARIOS:                                   
-----------------------------------------------------------------------------------------------------------------------------
 NAME                                📦 STATUS    VERSION  LOCAL PATH                                                        
-----------------------------------------------------------------------------------------------------------------------------
 crowdsec/http-crawl-non_statics     ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-crawl-non_statics.yaml    
 crowdsec/iptables-scan-multi_ports  ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/iptables-scan-multi_ports.yaml 
 crowdsec/http-scan-uniques_404      ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-scan-uniques_404.yaml     
 crowdsec/ssh-bf                     ✔️  enabled  0.8      /etc/crowdsec/config/scenarios/ssh-bf.yaml                    
-----------------------------------------------------------------------------------------------------------------------------
INFO[0000] COLLECTIONS:                                 
-------------------------------------------------------------------------------------------------------------------
 NAME                          📦 STATUS    VERSION  LOCAL PATH                                                    
-------------------------------------------------------------------------------------------------------------------
 crowdsec/base-http-scenarios  ✔️  enabled  0.1      /etc/crowdsec/config/collections/base-http-scenarios.yaml 
 crowdsec/iptables             ✔️  enabled  0.2      /etc/crowdsec/config/collections/iptables.yaml            
 crowdsec/nginx                ✔️  enabled  0.2      /etc/crowdsec/config/collections/nginx.yaml               
 crowdsec/sshd                 ✔️  enabled  0.2      /etc/crowdsec/config/collections/sshd.yaml                
 crowdsec/linux                ✔️  enabled  0.2      /etc/crowdsec/config/collections/linux.yaml               
-------------------------------------------------------------------------------------------------------------------
INFO[0000] POSTOVERFLOWS:                               
--------------------------------------
 NAME  📦 STATUS  VERSION  LOCAL PATH 
--------------------------------------
--------------------------------------
```
</details>




## Finding configurations

{{v0X.crowdsec.Name}} efficiency is dictated by installed parsers and scenarios, so [take a look at the {{v0X.hub.name}}]({{v0X.hub.url}}) to find the appropriated ones !

If you didn't perform the setup with the wizard, or if you are reading logs from other machines, you will have to pick the right {{v0X.collections.htmlname}}. This will ensure that {{v0X.crowdsec.name}} can parse the logs and has the corresponding scenarios.

For example, if you're processing [nginx](http://nginx.org) logs, you might want to install the [nginx collection](https://hub.crowdsec.net/author/crowdsecurity/collections/nginx).

A collection can be installed by typing `cscli install collection crowdsecurity/nginx`, and provides all the necessary parsers and scenarios to handle said log source. `systemctl reload crowdsec` to ensure the new scenarios are loaded.

In the same spirit, the [crowdsecurity/sshd](https://hub.crowdsec.net/author/crowdsecurity/collections/sshd)'s collection will fit most sshd setups !

While {{v0X.crowdsec.name}} is running, a quick look at [`cscli metrics`](/Crowdsec/v0/observability/command_line/) should help you ensure that your log sources are correctly parsed.


## List existing bans

> List current bans

```bash
{{v0X.cli.bin}} ban list
```


On the machine where you deployed {{v0X.crowdsec.name}}, type `{{v0X.cli.bin}} ban list` to see existing bans.
If you just deployed {{v0X.crowdsec.name}}, the list might be empty, but don't worry, it simply means you haven't yet been attacked, congrats!

Check [{{v0X.cli.name}} ban](/Crowdsec/v0/cheat_sheets/ban-mgmt/) management for more !


<details>
  <summary>output example</summary>
```bash
bui@sd:~$ {{v0X.cli.bin}} ban list
7 local decisions:
+--------+----------------+--------------------------------+------+--------+---------+--------------------------------+--------+------------+
| SOURCE |       IP       |             REASON             | BANS | ACTION | COUNTRY |               AS               | EVENTS | EXPIRATION |
+--------+----------------+--------------------------------+------+--------+---------+--------------------------------+--------+------------+
| local  | 103.218.xxx.xx | crowdsecurity/ssh-bf           |    4 | ban    | HK      | 59077 Shanghai UCloud          |     24 | 3h28m24s   |
|        |                |                                |      |        |         | Information Technology Company |        |            |
|        |                |                                |      |        |         | Limited                        |        |            |
| local  | 176.174.x.xx   | crowdsecurity/ssh-bf           |   11 | ban    | FR      | 5410 Bouygues Telecom SA       |     66 | 2h48m6s    |
| local  | 37.49.xxx.xxx  | crowdsecurity/ssh-bf           |    4 | ban    | NL      |                             0  |     37 | 2h16m35s   |
| local  | 37.49.xxx.xx   | crowdsecurity/ssh-bf_user-enum |    5 | ban    | NL      |                             0  |     59 | 2h16m21s   |
| local  | 92.246.xx.xxx  | crowdsecurity/ssh-bf_user-enum |    2 | ban    |         |                             0  |     12 | 1h42m2s    |
| local  | 23.237.x.xx    | crowdsecurity/ssh-bf           |    8 | ban    | US      | 174 Cogent Communications      |     48 | 1h7m48s    |
| local  | 185.153.xxx.xx | crowdsecurity/ssh-bf_user-enum |   59 | ban    | MD      | 49877 RM Engineering LLC       |    449 | 12m54s     |
+--------+----------------+--------------------------------+------+--------+---------+--------------------------------+--------+------------+
And 64 records from API, 32 distinct AS, 19 distinct countries
```
</details>

There are different bans sources:

  - local : bans triggered locally 
  - api : bans fetched from the API as part of the global consensus
  - cli : bans added via `{{v0X.cli.bin}} ban add`

## Monitor on-going activity (prometheus)

> List metrics

```bash
{{v0X.cli.bin}} metrics
```

The metrics displayed are extracted from {{v0X.crowdsec.name}} prometheus.
The indicators are grouped by scope :

 - Buckets : Know which buckets are created and/or overflew (scenario efficiency)
 - Acquisition : Know which file produce logs and if thy are parsed (or end up in bucket)
 - Parser : Know how frequently the individual parsers are triggered and their success rate

<details>
  <summary>output example</summary>

```bash
bui@sd:~$ {{v0X.cli.bin}}  metrics
INFO[0000] Buckets Metrics:                             
+---------------------------------+-----------+--------------+--------+---------+
|             BUCKET              | OVERFLOWS | INSTANTIATED | POURED | EXPIRED |
+---------------------------------+-----------+--------------+--------+---------+
| crowdsec/http-scan-uniques_404  |        69 |           77 |    424 |       8 |
| crowdsec/ssh-bf                 |         4 |           23 |     53 |      18 |
| crowdsec/ssh-bf_user-enum       | -         |           21 |     23 |      20 |
| crowdsec/http-crawl-non_statics |         9 |           14 |    425 |       5 |
+---------------------------------+-----------+--------------+--------+---------+
INFO[0000] Acquisition Metrics:                         
+------------------------------------------+------------+--------------+----------------+------------------------+
|                  SOURCE                  | LINES READ | LINES PARSED | LINES UNPARSED | LINES POURED TO BUCKET |
+------------------------------------------+------------+--------------+----------------+------------------------+
| /var/log/nginx/error.log                 |        496 |          496 | -              | -                      |
| /var/log/nginx/http.access.log  |        472 |          465 |              7 |                    847 |
| /var/log/nginx/https.access.log |          1 |            1 | -              |                      2 |
| /var/log/auth.log                        |        357 |           53 |            304 |                     76 |
| /var/log/kern.log                        |       2292 | -            |           2292 | -                      |
| /var/log/syslog                          |       2358 | -            |           2358 | -                      |
+------------------------------------------+------------+--------------+----------------+------------------------+
INFO[0000] Parser Metrics:                              
+---------------------------+------+--------+----------+
|          PARSERS          | HITS | PARSED | UNPARSED |
+---------------------------+------+--------+----------+
| crowdsec/syslog-logs      | 5007 |   5007 |        0 |
| crowdsec/whitelists       | 1015 |   1015 |        0 |
| crowdsec/dateparse-enrich | 1015 |   1015 |        0 |
| crowdsec/geoip-enrich     |  519 |    519 |        0 |
| crowdsec/http-logs        |  962 |    427 |      535 |
| crowdsec/nginx-logs       |  973 |    962 |       11 |
| crowdsec/non-syslog       |  969 |    969 |        0 |
| crowdsec/sshd-logs        |  350 |     53 |      297 |
+---------------------------+------+--------+----------+

```

</details>

## Monitor on-going activity (log files)

The {{v0X.crowdsec.main_log}} file will tell you what is going on and when an IP is blocked.

Check [{{v0X.crowdsec.name}} monitoring](/Crowdsec/v0/observability/overview/) for more !


<details>
  <summary>output example</summary>


```bash
bui@sd:~$ tail -f /var/log/crowdsec-agent.log 
time="14-04-2020 16:06:21" level=warning msg="40 existing LeakyRoutine"
time="14-04-2020 16:14:07" level=warning msg="1.2.3.4 triggered a 4h0m0s ip ban remediation for [crowdsec/ssh-bf]" bucket_id=throbbing-forest event_time="2020-04-14 16:14:07.215101505 +0200 CEST m=+359659.646220115" scenario=crowdsec/ssh-bf source_ip=1.2.3.4
time="14-04-2020 16:15:52" level=info msg="api push signal: token renewed. Pushing signals"
time="14-04-2020 16:15:53" level=info msg="api push signal: pushed 1 signals successfully"
time="14-04-2020 16:21:10" level=warning msg="18 existing LeakyRoutine"
time="14-04-2020 16:30:01" level=info msg="Flushed 1 expired entries from Ban Application"
time="14-04-2020 16:33:23" level=warning msg="33 existing LeakyRoutine"
time="14-04-2020 16:35:58" level=info msg="Flushed 1 expired entries from Ban Application"

```

</details>
