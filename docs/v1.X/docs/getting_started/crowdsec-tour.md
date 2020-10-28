
## List installed configurations


```bash
$ {{v1X.cli.bin}} hub list

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


## Finding configurations

{{v1X.crowdsec.Name}} efficiency is dictated by installed parsers and scenarios, often bundled together as {{v1X.collections.Htmlname}} so take a look at the {{v1X.hub.htmlname}} to find the appropriated ones !

You will have to pick the right {{v1X.collections.htmlname}}. This will ensure that {{v1X.crowdsec.name}} can parse the logs and has the corresponding scenarios.

For example, if you're processing [nginx](http://nginx.org) logs, you might want to install the [nginx collection](https://hub.crowdsec.net/author/crowdsecurity/collections/nginx).

A collection can be installed by typing `cscli collections install crowdsecurity/nginx`, and provides all the necessary parsers and scenarios to handle said log source. `systemctl reload crowdsec` to ensure the new scenarios are loaded.

In the same spirit, the [crowdsecurity/sshd](https://hub.crowdsec.net/author/crowdsecurity/collections/sshd)'s collection will fit most sshd setups !

While {{v1X.crowdsec.name}} is running, a quick look at [`cscli metrics`](/Crowdsec/v1/observability/command_line/) should help you ensure that your log sources are correctly parsed.


## List existing bans


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

## Monitor on-going activity (prometheus)

> List metrics

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

## Monitor on-going activity (log files)

The {{v1X.crowdsec.main_log}} file will tell you what is going on and when an IP is blocked.

Check [{{v1X.crowdsec.name}} monitoring](/Crowdsec/v1/observability/overview/) for more !

