
## List installed configurations

```bash
sudo {{v1X.cli.bin}} hub list
```

On the machine where you deployed {{v1X.crowdsec.name}}, type `sudo {{v1X.cli.bin}} hub list` to see install configurations.
This list represents the parsers, scenarios and/or collections that you deployed. They represent what your {{v1X.crowdsec.name}} setup can read (logs) and detect (scenarios). `sudo {{v1X.cli.bin}} hub list -a` will list all available configurations in the hub.


Check [{{v1X.cli.name}} configuration](/Crowdsec/v1/user_guide/cscli/) management for more !

<details>
  <summary>output example</summary>
```bash
$ sudo cscli hub list
INFO[0000] Loaded 13 collecs, 17 parsers, 21 scenarios, 3 post-overflow parsers 
INFO[0000] unmanaged items : 23 local, 0 tainted        
INFO[0000] PARSERS:                                     
--------------------------------------------------------------------------------------------------------------
 NAME                            📦 STATUS    VERSION  LOCAL PATH                                             
--------------------------------------------------------------------------------------------------------------
 crowdsecurity/mysql-logs        ✔️  enabled  0.1      /etc/crowdsec/parsers/s01-parse/mysql-logs.yaml        
 crowdsecurity/sshd-logs         ✔️  enabled  0.1      /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml         
 crowdsecurity/dateparse-enrich  ✔️  enabled  0.1      /etc/crowdsec/parsers/s02-enrich/dateparse-enrich.yaml 
 crowdsecurity/whitelists        ✔️  enabled  0.1      /etc/crowdsec/parsers/s02-enrich/whitelists.yaml       
 crowdsecurity/geoip-enrich      ✔️  enabled  0.2      /etc/crowdsec/parsers/s02-enrich/geoip-enrich.yaml     
 crowdsecurity/syslog-logs       ✔️  enabled  0.1      /etc/crowdsec/parsers/s00-raw/syslog-logs.yaml         
--------------------------------------------------------------------------------------------------------------
INFO[0000] SCENARIOS:                                   
-------------------------------------------------------------------------------------
 NAME                    📦 STATUS    VERSION  LOCAL PATH                            
-------------------------------------------------------------------------------------
 crowdsecurity/mysql-bf  ✔️  enabled  0.1      /etc/crowdsec/scenarios/mysql-bf.yaml 
 crowdsecurity/ssh-bf    ✔️  enabled  0.1      /etc/crowdsec/scenarios/ssh-bf.yaml   
-------------------------------------------------------------------------------------
INFO[0000] COLLECTIONS:                                 
---------------------------------------------------------------------------------
 NAME                 📦 STATUS    VERSION  LOCAL PATH                           
---------------------------------------------------------------------------------
 crowdsecurity/mysql  ✔️  enabled  0.1      /etc/crowdsec/collections/mysql.yaml 
 crowdsecurity/sshd   ✔️  enabled  0.1      /etc/crowdsec/collections/sshd.yaml  
 crowdsecurity/linux  ✔️  enabled  0.2      /etc/crowdsec/collections/linux.yaml 
---------------------------------------------------------------------------------
INFO[0000] POSTOVERFLOWS:                               
--------------------------------------
 NAME  📦 STATUS  VERSION  LOCAL PATH 
--------------------------------------
--------------------------------------

```
</details>

## Installing configurations

```bash
sudo cscli <configuration_type> install <item>
```

`configuration_type` can be:

 - [`parsers`](https://docs.crowdsec.net/Crowdsec/v1/references/parsers/)

 - [`scenarios`](https://docs.crowdsec.net/Crowdsec/v1/references/scenarios/)

 - [`postoverflows`](https://docs.crowdsec.net/Crowdsec/v1/references/postoverflows/)

 - [`collections`](https://docs.crowdsec.net/Crowdsec/v1/references/collections/)


They can be found and browsed on the {{v1X.hub.htmlname}}

## Upgrading configurations

```bash
sudo cscli <configuration_type> upgrade <item>
```

`configuration_type` can be:

 - [`parsers`](https://docs.crowdsec.net/Crowdsec/v1/references/parsers/)

 - [`scenarios`](https://docs.crowdsec.net/Crowdsec/v1/references/scenarios/)

 - [`postoverflows`](https://docs.crowdsec.net/Crowdsec/v1/references/postoverflows/)

 - [`collections`](https://docs.crowdsec.net/Crowdsec/v1/references/collections/)

They can be found and browsed on the {{v1X.hub.htmlname}}

## List active decisions


```bash
sudo {{v1X.cli.bin}} decisions list
```

If you just deployed {{v1X.crowdsec.name}}, the list might be empty, but don't worry, it simply means you haven't yet been attacked, congrats!

Check [{{v1X.cli.name}} decisions](/Crowdsec/v1/user_guide/decision_management/) management for more !


<details>
  <summary>output example</summary>
```bash
$ sudo cscli decisions list
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
| ID  | SOURCE    | SCOPE:VALUE |               REASON               | ACTION | COUNTRY | AS | EVENTS |     EXPIRATION     | ALERT ID |
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
| 802 | cscli     | Ip:1.2.3.5  | manual 'ban' from                  | ban    |         |    |      1 | 3h50m58.10039043s  |     802  |
|     |           |             | 'b76cc7b1bbdc489e93909d2043031de8' |        |         |    |        |                    |          |
| 801 | crowdsec  | Ip:1.2.3.4  | crowdsecurity/ssh-bf               | ban    |         |    |      6 | 3h59m45.100387557s |     801  |
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
```
</details>

There are different decisions `SOURCE`:

  - crowdsec : decisions triggered locally by the crowdsec agent 
  - CAPI : decisions fetched from the Crowdsec Central API
  - csli : decisions added via `sudo {{v1X.cli.bin}} decisions add`


## List alerts


```bash
sudo {{v1X.cli.bin}} alerts list
```

While decisions won't be shown anymore once they expire (or are manually deleted), the alerts will stay visible, allowing you to keep track of past decisions.
You will here see the alerts, even if the associated decisions expired.

<details>
  <summary>output example</summary>
```bash
$ sudo cscli alerts list --since 1h
+----+-------------+----------------------------+---------+----+-----------+---------------------------+
| ID | SCOPE:VALUE |           REASON           | COUNTRY | AS | DECISIONS |        CREATED AT         |
+----+-------------+----------------------------+---------+----+-----------+---------------------------+
|  5 | Ip:1.2.3.6  | crowdsecurity/ssh-bf (0.1) | US      |    | ban:1     | 2020-10-29T11:33:36+01:00 |
+----+-------------+----------------------------+---------+----+-----------+---------------------------+
```
</details>


## Monitor on-going activity (prometheus)

```bash
sudo {{v1X.cli.bin}} metrics
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
$ sudo {{v1X.cli.bin}} metrics
INFO[0000] Buckets Metrics:
+--------------------------------------+---------------+-----------+--------------+--------+---------+
|                BUCKET                | CURRENT COUNT | OVERFLOWS | INSTANCIATED | POURED | EXPIRED |
+--------------------------------------+---------------+-----------+--------------+--------+---------+
| crowdsecurity/http-bad-user-agent    | -             | -         |            7 |      7 |       7 |
| crowdsecurity/http-crawl-non_statics | -             | -         |           82 |    107 |      82 |
| crowdsecurity/http-probing           | -             | -         |            2 |      2 |       2 |
| crowdsecurity/http-sensitive-files   | -             | -         |            1 |      1 |       1 |
| crowdsecurity/ssh-bf                 |            16 |      5562 |         7788 |  41542 |    2210 |
| crowdsecurity/ssh-bf_user-enum       |             8 | -         |         6679 |  12571 |    6671 |
+--------------------------------------+---------------+-----------+--------------+--------+---------+
INFO[0000] Acquisition Metrics:
+---------------------------+------------+--------------+----------------+------------------------+
|          SOURCE           | LINES READ | LINES PARSED | LINES UNPARSED | LINES POURED TO BUCKET |
+---------------------------+------------+--------------+----------------+------------------------+
| /var/log/auth.log         |      92978 |        41542 |          51436 |                  54113 |
| /var/log/messages         |          2 | -            |              2 | -                      |
| /var/log/nginx/access.log |        124 |           99 |             25 |                     88 |
| /var/log/nginx/error.log  |        287 |           63 |            224 |                     29 |
| /var/log/syslog           |      27271 | -            |          27271 | -                      |
+---------------------------+------------+--------------+----------------+------------------------+
INFO[0000] Parser Metrics:
+--------------------------------+--------+--------+----------+
|            PARSERS             |  HITS  | PARSED | UNPARSED |
+--------------------------------+--------+--------+----------+
| child-crowdsecurity/http-logs  |    486 |    232 |      254 |
| child-crowdsecurity/nginx-logs |    723 |    162 |      561 |
| child-crowdsecurity/sshd-logs  | 381792 |  41542 |   340250 |
| crowdsecurity/dateparse-enrich |  41704 |  41704 | -        |
| crowdsecurity/geoip-enrich     |  41641 |  41641 | -        |
| crowdsecurity/http-logs        |    162 |     59 |      103 |
| crowdsecurity/nginx-logs       |    411 |    162 |      249 |
| crowdsecurity/non-syslog       |    411 |    411 | -        |
| crowdsecurity/sshd-logs        |  92126 |  41542 |    50584 |
| crowdsecurity/syslog-logs      | 120251 | 120249 |        2 |
| crowdsecurity/whitelists       |  41704 |  41704 | -        |
+--------------------------------+--------+--------+----------+
INFO[0000] Local Api Metrics:
+----------------------+--------+------+
|        ROUTE         | METHOD | HITS |
+----------------------+--------+------+
| /v1/alerts           | GET    |    3 |
| /v1/alerts           | POST   | 4673 |
| /v1/decisions/stream | GET    | 6498 |
| /v1/watchers/login   | POST   |   23 |
+----------------------+--------+------+
INFO[0000] Local Api Machines Metrics:
+----------------------------------+------------+--------+------+
|             MACHINE              |   ROUTE    | METHOD | HITS |
+----------------------------------+------------+--------+------+
| 7f0607a3469243139699bf2f30321fc4 | /v1/alerts | POST   | 4673 |
| 7f0607a3469243139699bf2f30321fc4 | /v1/alerts | GET    |    3 |
+----------------------------------+------------+--------+------+
INFO[0000] Local Api Bouncers Metrics:
+------------------------------+----------------------+--------+------+
|           BOUNCER            |        ROUTE         | METHOD | HITS |
+------------------------------+----------------------+--------+------+
| cs-firewall-bouncer-n3W19Qua | /v1/decisions/stream | GET    | 6498 |
+------------------------------+----------------------+--------+------+
```

</details>

### Reading metrics

Those metrics are a great way to know if your configuration is correct :

The `Acquisition Metrics` is a great way to know if your parsers are setup correctly :

 - If you have 0 **LINES PARSED** for a source : You are probably *missing* a parser, or you have a custom log format that prevents the parser from understanding your logs.
 - However, it's perfectly OK to have a lot of **LINES UNPARSED** : Crowdsec is not a SIEM, and only parses the logs that are relevant to its scenarios. For example, [ssh parser](https://hub.crowdsec.net/author/crowdsecurity/configurations/sshd-logs),  only cares about failed authentication events (at the time of writting).
 - **LINES POURED TO BUCKET** tell you that your scenarios are matching your log sources : it means that some events from this log source made all their way to an actual scenario


The `Parser Metrics` will let you troubleshoot eventual parser misconfigurations :

 - **HITS** is how many events where fed to this specific parser

 - **PARSED** and **UNPARSED** indicate how many events successfully come out of the parser


For example, if you have a custom log format in nginx that is not supported by the default parser, you will end up seeing a lot of **UNPARSED** for this specific parser, and 0 for **PARSED**.

For more advanced metrics understanding, [take a look at the dedicated prometheus documentation](/Crowdsec/v1/observability/prometheus/).


## Deploy dashboard

```bash
sudo cscli dashboard setup --listen 0.0.0.0
```

A docker metabase {{v1X.metabase.Htmlname}} container can be deployed with `cscli dashboard`.
It requires docker, [installation instructions are available here](https://docs.docker.com/engine/install/).

## Logs

```bash
sudo tail -f /var/log/crowdsec.log
```

 - `/var/log/crowdsec.log` is the main log, it shows ongoing decisions and acquisition/parsing/scenario errors.
 - `/var/log/crowdsec_api.log` is the access log of the local api (LAPI)


## Scalability

Crowdsec uses go-routines for parsing and enriching logs, pouring events to buckets and manage outputs.

By default, one routine of each exists (should be enough to handle ~1K EP/s), and can be changed in `crowdsec_service` of the main configuration file via the [parser_routines](/Crowdsec/v1/references/crowdsec-config/#parser_routines), [buckets_routines](/Crowdsec/v1/references/crowdsec-config/#buckets_routines) and [output_routines](/Crowdsec/v1/references/crowdsec-config/#output_routines) directives.

Please keep in mind that thanks to the [http API]({{v1X.lapi.swagger}}), the workload of log parsing can be splitted amongst several agents pushing to a single {{v1X.lapi.Htmlname}}.
