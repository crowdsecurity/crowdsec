```bash
sudo {{v1X.cli.name}} metrics
```

This command provides an overview of {{v1X.crowdsec.name}} statistics provided by [prometheus client](/Crowdsec/v1/observability/prometheus/). By default it assumes that the {{v1X.crowdsec.name}} is installed on the same machine.

The metrics are split in 3 main sections :

 - Acquisition metrics : How many lines were read from which sources, how many were successfully or unsuccessfully parsed, and how many of those lines ultimately ended up being poured to a bucket.
 - Parser metrics : How many lines were fed (eligible) to each parser, and how many of those were successfully or unsuccessfully parsed.
 - Bucket metrics : How many time each scenario lead to a bucket instantiation, and for each of those :
    - how many times it overflowed
    - how many times it expired (underflows)
    - how many subsequent events were poured to said bucket

!!! hint
    These metrics should help you identify potential configuration errors.

    For example, if you have a source that has mostly unparsed logs, you know you might be missing some parsers.
    As well, if you have scenarios that are never instantiated, it might be a hint that they are not relevant to your configuration.

<details>
  <summary>{{v1X.cli.name}} metrics example</summary>
```bash
$ sudo cscli metrics

INFO[0000] Buckets Metrics:
+--------------------------------------+---------------+-----------+--------------+--------+---------+
|                BUCKET                | CURRENT COUNT | OVERFLOWS | INSTANCIATED | POURED | EXPIRED |
+--------------------------------------+---------------+-----------+--------------+--------+---------+
| crowdsecurity/http-bad-user-agent    | -             | -         |           10 |     10 |      10 |
| crowdsecurity/http-crawl-non_statics | -             | -         |           91 |    119 |      91 |
| crowdsecurity/http-probing           | -             | -         |            2 |      2 |       2 |
| crowdsecurity/http-sensitive-files   | -             | -         |            1 |      1 |       1 |
| crowdsecurity/ssh-bf                 |            13 |      6314 |         8768 |  46772 |    2441 |
| crowdsecurity/ssh-bf_user-enum       |             6 | -         |         7646 |  14406 |    7640 |
+--------------------------------------+---------------+-----------+--------------+--------+---------+
INFO[0000] Acquisition Metrics:
+---------------------------+------------+--------------+----------------+------------------------+
|          SOURCE           | LINES READ | LINES PARSED | LINES UNPARSED | LINES POURED TO BUCKET |
+---------------------------+------------+--------------+----------------+------------------------+
| /var/log/auth.log         |     105476 |        46772 |          58704 |                  61178 |
| /var/log/messages         |          2 | -            |              2 | -                      |
| /var/log/nginx/access.log |        138 |          111 |             27 |                    100 |
| /var/log/nginx/error.log  |        312 |           68 |            244 |                     32 |
| /var/log/syslog           |      31919 | -            |          31919 | -                      |
+---------------------------+------------+--------------+----------------+------------------------+
INFO[0000] Parser Metrics:
+--------------------------------+--------+--------+----------+
|            PARSERS             |  HITS  | PARSED | UNPARSED |
+--------------------------------+--------+--------+----------+
| child-crowdsecurity/http-logs  |    537 |    257 |      280 |
| child-crowdsecurity/nginx-logs |    789 |    179 |      610 |
| child-crowdsecurity/sshd-logs  | 436048 |  46772 |   389276 |
| crowdsecurity/dateparse-enrich |  46951 |  46951 | -        |
| crowdsecurity/geoip-enrich     |  46883 |  46883 | -        |
| crowdsecurity/http-logs        |    179 |     66 |      113 |
| crowdsecurity/nginx-logs       |    450 |    179 |      271 |
| crowdsecurity/non-syslog       |    450 |    450 | -        |
| crowdsecurity/sshd-logs        | 104386 |  46772 |    57614 |
| crowdsecurity/syslog-logs      | 137397 | 137395 |        2 |
| crowdsecurity/whitelists       |  46951 |  46951 | -        |
+--------------------------------+--------+--------+----------+
INFO[0000] Local Api Metrics:
+----------------------+--------+------+
|        ROUTE         | METHOD | HITS |
+----------------------+--------+------+
| /v1/alerts           | GET    |    4 |
| /v1/alerts           | POST   | 5400 |
| /v1/decisions/stream | GET    | 7694 |
| /v1/watchers/login   | POST   |   27 |
+----------------------+--------+------+
INFO[0000] Local Api Machines Metrics:
+----------------------------------+------------+--------+------+
|             MACHINE              |   ROUTE    | METHOD | HITS |
+----------------------------------+------------+--------+------+
| 7f0607a3469243139699bf2f30321fc4 | /v1/alerts | GET    |    4 |
| 7f0607a3469243139699bf2f30321fc4 | /v1/alerts | POST   | 5400 |
+----------------------------------+------------+--------+------+
INFO[0000] Local Api Bouncers Metrics:
+------------------------------+----------------------+--------+------+
|           BOUNCER            |        ROUTE         | METHOD | HITS |
+------------------------------+----------------------+--------+------+
| cs-firewall-bouncer-n3W19Qua | /v1/decisions/stream | GET    | 7694 |
+------------------------------+----------------------+--------+------+

```
</details>