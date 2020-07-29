```bash
{{cli.name}} metrics
```

This command provides an overview of {{crowdsec.name}} statistics provided by [prometheus client](/observability/prometheus/). By default it assumes that the {{crowdsec.name}} is installed on the same machine.

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
  <summary>{{cli.name}} metrics example</summary>
```bash
INFO[0000] Buckets Metrics:                             
+-----------------------------------------+-----------+--------------+--------+---------+
|                 BUCKET                  | OVERFLOWS | INSTANTIATED | POURED | EXPIRED |
+-----------------------------------------+-----------+--------------+--------+---------+
| crowdsecurity/http-scan-uniques_404     | -         |            8 |      9 |       8 |
| crowdsecurity/iptables-scan-multi_ports |         1 |         8306 |   9097 |    8288 |
| crowdsecurity/ssh-bf                    |        42 |          281 |   1434 |     238 |
| crowdsecurity/ssh-bf_user-enum          |        13 |          659 |    777 |     646 |
| crowdsecurity/http-crawl-non_statics    | -         |           10 |     12 |      10 |
+-----------------------------------------+-----------+--------------+--------+---------+
INFO[0000] Acquisition Metrics:                         
+------------------------------------------+------------+--------------+----------------+------------------------+
|                  SOURCE                  | LINES READ | LINES PARSED | LINES UNPARSED | LINES POURED TO BUCKET |
+------------------------------------------+------------+--------------+----------------+------------------------+
| /var/log/nginx/https.access.log |         25 |           25 | -              |                      7 |
| /var/log/kern.log                        |      18078 |        18078 | -              |                   4066 |
| /var/log/syslog                          |      18499 |        18078 |            421 |                   5031 |
| /var/log/auth.log                        |       6086 |         1434 |           4652 |                   2211 |
| /var/log/nginx/error.log                 |     170243 |       169632 |            611 | -                      |
| /var/log/nginx/http.access.log  |         44 |           44 | -              |                     14 |
+------------------------------------------+------------+--------------+----------------+------------------------+
INFO[0000] Parser Metrics:                              
+--------------------------------+--------+--------+----------+
|            PARSERS             |  HITS  | PARSED | UNPARSED |
+--------------------------------+--------+--------+----------+
| crowdsecurity/geoip-enrich     |  37659 |  37659 |        0 |
| crowdsecurity/http-logs        | 169701 |     27 |   169674 |
| crowdsecurity/iptables-logs    |  36156 |  36156 |        0 |
| crowdsecurity/nginx-logs       | 170316 | 169701 |      615 |
| crowdsecurity/non-syslog       | 170312 | 170312 |        0 |
| crowdsecurity/sshd-logs        |   6053 |   1434 |     4619 |
| crowdsecurity/syslog-logs      |  42663 |  42663 |        0 |
| crowdsecurity/dateparse-enrich | 207291 | 207291 |        0 |
+--------------------------------+--------+--------+----------+

```
</details>