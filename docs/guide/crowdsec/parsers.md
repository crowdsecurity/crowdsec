
## Listing installed parsers

{{parsers.Htmlname}} are yaml files in `{{config.crowdsec_dir}}parsers/<STAGE>/parser.yaml`.

!!! info

    Alphabetical file order dictates the order of {{stage.htmlname}} and the orders of parsers within stage.

You can use the following command to view installed parsers:

```
{{cli.bin}} list parsers
```

<details>
  <summary>{{cli.name}} list example</summary>

```bash
# {{cli.name}} list parsers
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
--------------------------------------------------------------------------------------------------------------------
 NAME                       📦 STATUS    VERSION  LOCAL PATH                                                        
--------------------------------------------------------------------------------------------------------------------
 crowdsec/iptables-logs     ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/iptables-logs.yaml     
 crowdsec/dateparse-enrich  ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/dateparse-enrich.yaml 
 crowdsec/sshd-logs         ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/sshd-logs.yaml         
 crowdsec/whitelists        ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/whitelists.yaml       
 crowdsec/http-logs         ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/http-logs.yaml        
 crowdsec/nginx-logs        ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/nginx-logs.yaml        
 crowdsec/syslog-logs       ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml         
 crowdsec/geoip-enrich      ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/geoip-enrich.yaml     
--------------------------------------------------------------------------------------------------------------------
```

</details>


## Installing parsers

### From the hub

[{{hub.name}}]({{hub.parsers_url}}) allows you to find needed scenarios, just paste the command on your machine :

![Hub Screenshot](/assets/images/hub_parser.png)

```bash
# {{cli.name}} install parser crowdsec/nginx-logs
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
INFO[0000] crowdsec/nginx-logs : OK                     
INFO[0000] Enabled parsers : crowdsec/nginx-logs        
INFO[0000] Enabled crowdsec/nginx-logs                  
# systemctl reload crowdsec
```

### Your own parsers

[Write your parser configuration](/write_configurations/parsers/) and deploy yaml file in `{{config.crowdsec_dir}}parsers/<STAGE>/`.



## Monitoring parsers behavior

{{cli.name}} allows you to view {{crowdsec.name}} metrics info via the `metrics` command.
This allows you to see how many logs were ingested and then parsed or unparsed by said parser.

You can see those metrics with the following command:
```
cscli metrics
```

<details>
  <summary>{{cli.name}} metrics example</summary>

```bash
# {{cli.name}} metrics
...
INFO[0000] Parser Metrics:                              
+---------------------------+--------+--------+----------+
|          PARSERS          |  HITS  | PARSED | UNPARSED |
+---------------------------+--------+--------+----------+
| crowdsec/sshd-logs        |  62424 |  12922 |    49502 |
| crowdsec/syslog-logs      | 667417 | 667417 |        0 |
| crowdsec/whitelists       | 610901 | 610901 |        0 |
| crowdsec/http-logs        |    136 |     21 |      115 |
| crowdsec/iptables-logs    | 597843 | 597843 |        0 |
| crowdsec/nginx-logs       |    137 |    136 |        1 |
| crowdsec/dateparse-enrich | 610901 | 610901 |        0 |
| crowdsec/geoip-enrich     | 610836 | 610836 |        0 |
| crowdsec/non-syslog       |    137 |    137 |        0 |
+---------------------------+--------+--------+----------+

```

</details>


## Going further

If you're interested into [understanding how parsers are made](/references/parsers/) or writing your own, please have a look at [this page](/write_configurations/parsers/).

