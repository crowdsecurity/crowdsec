Scenarios are yaml files that define "buckets".
Most of the scenarios currently rely on the [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket) concept.
Scenarios lead to the instantiation, and sometime the overflow, of buckets.


When a bucket "overflows", the scenario is considered as having been realized.
This event leads to the creation of a new {{v0X.event.htmlname}} that describes the scenario that just happened (via a {{v0X.signal.htmlname}}).


## Listing installed scenarios

scenarios are yaml files in `{{v0X.config.crowdsec_dir}}scenarios/<scenario>.yaml`.

You can view installed scenarios with the following command:
```
{{v0X.cli.bin}} list scenarios
```


<details>
  <summary>{{v0X.cli.name}} list example</summary>

```bash
# {{v0X.cli.name}}  list scenarios
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
-----------------------------------------------------------------------------------------------------------------------------
 NAME                                📦 STATUS    VERSION  LOCAL PATH                                                        
-----------------------------------------------------------------------------------------------------------------------------
 crowdsec/http-scan-uniques_404      ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-scan-uniques_404.yaml     
 crowdsec/ssh-bf                     ✔️  enabled  0.8      /etc/crowdsec/config/scenarios/ssh-bf.yaml                    
 crowdsec/http-crawl-non_statics     ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-crawl-non_statics.yaml    
 crowdsec/iptables-scan-multi_ports  ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/iptables-scan-multi_ports.yaml 
-----------------------------------------------------------------------------------------------------------------------------
```

</details>

## Installing scenarios

### From the hub

{{v0X.hub.htmlname}} allows you to find needed scenarios.


```bash
# {{v0X.cli.name}} install scenario crowdsec/ssh-bf
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
INFO[0000] crowdsec/ssh-bf : OK                     
INFO[0000] Enabled scenarios : crowdsec/ssh-bf        
INFO[0000] Enabled crowdsec/ssh-bf               
# systemctl reload crowdsec
```

### Your own scenarios

[Write your scenario configuration](/Crowdsec/v0/write_configurations/scenarios/) and deploy yaml file in `{{v0X.config.crowdsec_dir}}scenarios/<scenario.yaml>`.




## Monitoring scenarios behavior

{{v0X.cli.name}} allows you to view {{v0X.crowdsec.name}} metrics info via the `metrics` command.
This allows you to see how many "buckets" associated to each scenario have been created (an event eligible from said scenario has arrived), poured (how many subsequent events have been pushed to said bucket), overflowed (the scenario happened) or underflow (there was not enough event to make the bucket overflow, and it thus expired after a while).

You can see those metrics with the following command:
```
{{v0X.cli.bin}} metrics
```


<details>
  <summary>{{v0X.cli.name}} metrics example</summary>

```bash
# {{v0X.cli.name}} metrics
INFO[0000] Buckets Metrics:                             
+------------------------------------+-----------+--------------+--------+---------+
|               BUCKET               | OVERFLOWS | INSTANTIATED | POURED | EXPIRED |
+------------------------------------+-----------+--------------+--------+---------+
| crowdsec/http-crawl-non_statics    | -         |            9 |     14 |       9 |
| crowdsec/http-scan-uniques_404     | -         |           11 |     14 |      11 |
| crowdsec/iptables-scan-multi_ports |        13 |       125681 | 141601 |  125650 |
| crowdsec/ssh-bf                    |       669 |         3721 |  12925 |    3046 |
| crowdsec/ssh-bf_user-enum          |       136 |         4093 |   7587 |    3956 |
+------------------------------------+-----------+--------------+--------+---------+
```

</details>

