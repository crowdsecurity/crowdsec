
## List installed configurations

```bash
{{v1X.cli.bin}} hub list

```

On the machine where you deployed {{v1X.crowdsec.name}}, type `{{v1X.cli.bin}} hub list` to see install configurations.
This list represents the parsers, scenarios and/or collections that you deployed. They represent what your {{v1X.crowdsec.name}} setup can read (logs) and detect (scenarios). `{{v1X.cli.bin}} hub list -a` will list all available configurations in the hub.


Check [{{v1X.cli.name}} configuration](/Crowdsec/v1/guide/cscli/) management for more !

<details>
  <summary>output example</summary>
```bash
$ ./cscli -c dev.yaml  hub list   
INFO[0000] Loaded 13 collecs, 17 parsers, 20 scenarios, 3 post-overflow parsers 
INFO[0000] unmanaged items : 7 local, 0 tainted         
INFO[0000] PARSERS:                                     
----------------------------------------------------------------------------------------------------------------------------------------------------------------
 NAME                            📦 STATUS    VERSION  LOCAL PATH                                                                                               
----------------------------------------------------------------------------------------------------------------------------------------------------------------
 crowdsecurity/syslog-logs       ✔️  enabled  0.1      /.../config/parsers/s00-raw/syslog-logs.yaml         
 crowdsecurity/dateparse-enrich  ✔️  enabled  0.1      /.../config/parsers/s02-enrich/dateparse-enrich.yaml 
 crowdsecurity/geoip-enrich      ✔️  enabled  0.2      /.../config/parsers/s02-enrich/geoip-enrich.yaml     
 crowdsecurity/sshd-logs         ✔️  enabled  0.1      /.../config/parsers/s01-parse/sshd-logs.yaml         
----------------------------------------------------------------------------------------------------------------------------------------------------------------
INFO[0000] SCENARIOS:                                   
-----------------------------------------------------------------------------------------------------------------------------------
 NAME                  📦 STATUS    VERSION  LOCAL PATH                                                                            
-----------------------------------------------------------------------------------------------------------------------------------
 crowdsecurity/ssh-bf  ✔️  enabled  0.1      /.../config/scenarios/ssh-bf.yaml 
-----------------------------------------------------------------------------------------------------------------------------------
INFO[0000] COLLECTIONS:                                 
-----------------------------------------------------------------------------------------------------------------------------------
 NAME                 📦 STATUS    VERSION  LOCAL PATH                                                                             
-----------------------------------------------------------------------------------------------------------------------------------
 crowdsecurity/sshd   ✔️  enabled  0.1      /.../config/collections/sshd.yaml  
 crowdsecurity/linux  ✔️  enabled  0.2      /.../config/collections/linux.yaml 
-----------------------------------------------------------------------------------------------------------------------------------
INFO[0000] POSTOVERFLOWS:                               
--------------------------------------
 NAME  📦 STATUS  VERSION  LOCAL PATH 
--------------------------------------
--------------------------------------
```
</details>

## List active decisions


```bash
{{v1X.cli.bin}} decisions list
```

If you just deployed {{v1X.crowdsec.name}}, the list might be empty, but don't worry, it simply means you haven't yet been attacked, congrats!

Check [{{v1X.cli.name}} ban](/Crowdsec/v1/cheat_sheets/ban-mgmt/) management for more !


<details>
  <summary>output example</summary>
```bash
$ cscli decisions list
+----+----------+-------------+----------------------+--------+---------+----+--------+------------------+
| ID |  SOURCE  | SCOPE:VALUE |        REASON        | ACTION | COUNTRY | AS | EVENTS |    EXPIRATION    |
+----+----------+-------------+----------------------+--------+---------+----+--------+------------------+
|  1 | crowdsec | Ip:1.2.3.6  | crowdsecurity/ssh-bf | ban    | US      |    |      6 | 59m48.467053872s |
|  2 | cscli    | Ip:1.2.3.4  |                      | ban    |         |    |      1 | 3h59m57.671401352s |
+----+----------+-------------+----------------------+--------+---------+----+--------+--------------------+
```
</details>

There are different bans sources:

  - crowdsec : bans triggered locally 
  - api : bans fetched from the API as part of the global consensus
  - csli : bans added via `{{v1X.cli.bin}} decisions add`


## List alerts


```bash
{{v1X.cli.bin}} alerts list
```

While decisions won't be shown anymore once they expire (or are manually deleted), the alerts will stay visible, allowing you to keep track of past decisions.
You will here see the alerts, even if the associated decisions expired.

<details>
  <summary>output example</summary>
```bash
$ cscli alerts list --since 1h
+----+-------------+----------------------------+---------+----+-----------+---------------------------+
| ID | SCOPE:VALUE |           REASON           | COUNTRY | AS | DECISIONS |        CREATED AT         |
+----+-------------+----------------------------+---------+----+-----------+---------------------------+
|  5 | Ip:1.2.3.6  | crowdsecurity/ssh-bf (0.1) | US      |    | ban:1     | 2020-10-29T11:33:36+01:00 |
+----+-------------+----------------------------+---------+----+-----------+---------------------------+

```
</details>


## Monitor on-going activity (prometheus)

```bash
{{v1X.cli.bin}} metrics
```

The metrics displayed are extracted from {{v1X.crowdsec.name}} prometheus.
The indicators are grouped by scope :

 - Buckets : Know which buckets are created and/or overflew (scenario efficiency)
 - Acquisition : Know which file produce logs and if thy are parsed (or end up in bucket)
 - Parser : Know how frequently the individual parsers are triggered and their success rate
 - Local Api Metrics : Know how often each endpoint of crowdsec's local API has been used

<details>
  <summary>output example</summary>

```bash
$ {{v1X.cli.bin}}  metrics
INFO[0000] Buckets Metrics:                             
+--------------------------------+---------------+-----------+--------------+--------+---------+
|             BUCKET             | CURRENT COUNT | OVERFLOWS | INSTANCIATED | POURED | EXPIRED |
+--------------------------------+---------------+-----------+--------------+--------+---------+
| crowdsecurity/ssh-bf           |             1 |         1 |            2 |     10 | -       |
| crowdsecurity/ssh-bf_user-enum |             1 | -         |            1 |      1 | -       |
+--------------------------------+---------------+-----------+--------------+--------+---------+
INFO[0000] Acquisition Metrics:                         
+-------------------+------------+--------------+----------------+------------------------+
|      SOURCE       | LINES READ | LINES PARSED | LINES UNPARSED | LINES POURED TO BUCKET |
+-------------------+------------+--------------+----------------+------------------------+
| /tmp/test.log     |         10 |           10 | -              |                     11 |
| /var/log/auth.log |          2 | -            |              2 | -                      |
| /var/log/syslog   |          4 | -            |              4 | -                      |
+-------------------+------------+--------------+----------------+------------------------+
INFO[0000] Parser Metrics:                              
+--------------------------------+------+--------+----------+
|            PARSERS             | HITS | PARSED | UNPARSED |
+--------------------------------+------+--------+----------+
| child-crowdsecurity/sshd-logs  |   10 |     10 | -        |
| crowdsecurity/dateparse-enrich |   10 |     10 | -        |
| crowdsecurity/geoip-enrich     |   10 |     10 | -        |
| crowdsecurity/sshd-logs        |   10 |     10 | -        |
| crowdsecurity/syslog-logs      |   16 |     16 | -        |
+--------------------------------+------+--------+----------+
INFO[0000] Local Api Metrics:                           
+--------------------+--------+------+
|       ROUTE        | METHOD | HITS |
+--------------------+--------+------+
| /v1/alerts         | GET    |    2 |
| /v1/alerts         | POST   |    2 |
| /v1/watchers/login | POST   |    4 |
+--------------------+--------+------+
```

</details>

## Deploy dashboard

```bash
cscli dashboard setup --listen 0.0.0.0
```

A docker metabase {{v1X.metabase.Htmlname}} container can be deployed with `cscli dashboard`.
It requires docker, [installation instructions are available here](https://docs.docker.com/engine/install/).

## Logs

```bash
tail -f /var/log/crowdsec.log
```

 - `/var/log/crowdsec.log` is the main log, it shows ongoing decisions and acquisition/parsing/scenario errors.
 - `/var/log/crowdsec_api.log` is the access log of the local api (LAPI)

## Installing collections

```bash
cscli collections install crowdsecurity/nginx
```

Collections are bundles of parsers/scenarios that form a coherent ensemble to analyze/detect attacks for a specific service. It is the most common way to deploy configurations.

They can be found and browsed on the {{v1X.hub.htmlname}}
