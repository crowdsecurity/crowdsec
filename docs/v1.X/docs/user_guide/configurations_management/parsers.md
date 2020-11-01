

## Installing parsers

```bash
$ cscli parsers install crowdsecurity/sshd-logs
```

[{{v1X.hub.name}}]({{v1X.hub.parsers_url}}) allows you to find needed parsers, just paste the command on your machine :

![Hub Screenshot](/Crowdsec/v1/assets/images/hub_parser.png)

<details>
  <summary>cscli parsers install example</summary>

```bash
$ cscli parsers install crowdsecurity/iptables-logs    
INFO[0000] crowdsecurity/iptables-logs : OK             
INFO[0000] Enabled parsers : crowdsecurity/iptables-logs 
INFO[0000] Enabled crowdsecurity/iptables-logs          
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
```
</details>

## Listing installed parsers

```bash
cscli parsers list
```

{{v1X.parsers.Htmlname}} are yaml files in `{{v1X.config.crowdsec_dir}}parsers/<STAGE>/parser.yaml`.




<details>
  <summary>cscli parsers list example</summary>

```bash
$ cscli parsers list
--------------------------------------------------------------------------------------------------------------
 NAME                            📦 STATUS    VERSION  LOCAL PATH                                             
--------------------------------------------------------------------------------------------------------------
 crowdsecurity/whitelists        ✔️  enabled  0.1      /etc/crowdsec/parsers/s02-enrich/whitelists.yaml       
 crowdsecurity/dateparse-enrich  ✔️  enabled  0.1      /etc/crowdsec/parsers/s02-enrich/dateparse-enrich.yaml 
 crowdsecurity/iptables-logs     ✔️  enabled  0.1      /etc/crowdsec/parsers/s01-parse/iptables-logs.yaml     
 crowdsecurity/syslog-logs       ✔️  enabled  0.1      /etc/crowdsec/parsers/s00-raw/syslog-logs.yaml         
 crowdsecurity/sshd-logs         ✔️  enabled  0.1      /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml         
 crowdsecurity/geoip-enrich      ✔️  enabled  0.2      /etc/crowdsec/parsers/s02-enrich/geoip-enrich.yaml     
 crowdsecurity/http-logs         ✔️  enabled  0.2      /etc/crowdsec/parsers/s02-enrich/http-logs.yaml        
 crowdsecurity/nginx-logs        ✔️  enabled  0.1      /etc/crowdsec/parsers/s01-parse/nginx-logs.yaml        
--------------------------------------------------------------------------------------------------------------

```

</details>


## Upgrading installed parsers

```bash
$ {{v1X.cli.bin}} parsers upgrade crowdsecurity/sshd-logs
```

Parsers upgrade allows you to upgrade an existing parser to the latest version.

<details>
  <summary>cscli parsers upgrade example</summary>

```bash
$ cscli collections upgrade crowdsecurity/sshd  
INFO[0000] crowdsecurity/sshd : up-to-date              
WARN[0000] crowdsecurity/sshd-logs : overwrite          
WARN[0000] crowdsecurity/ssh-bf : overwrite             
WARN[0000] crowdsecurity/sshd : overwrite               
INFO[0000] 📦 crowdsecurity/sshd : updated               
INFO[0000] Upgraded 1 items                             
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective.

```

</details>

## Monitoring parsers

```bash
$ cscli collections inspect crowdsecurity/sshd
```

Collections inspect will give you detailed information about a given collection, including versioning information *and* runtime metrics (fetched from prometheus).

<!--TBD: refaire l'output apres avoir fix le 'parsers inspect XXXX'-->
<details>
  <summary>cscli collections inspect example</summary>

```bash
$ cscli collections inspect crowdsecurity/sshd       
type: collections
name: crowdsecurity/sshd
filename: sshd.yaml
description: 'sshd support : parser and brute-force detection'
author: crowdsecurity
belongs_to_collections:
- crowdsecurity/linux
- crowdsecurity/linux
remote_path: collections/crowdsecurity/sshd.yaml
version: "0.1"
local_path: /etc/crowdsec/collections/sshd.yaml
localversion: "0.1"
localhash: 21159aeb87529efcf1a5033f720413d5321a6451bab679a999f7f01a7aa972b3
installed: true
downloaded: true
uptodate: true
tainted: false
local: false
parsers:
- crowdsecurity/sshd-logs
scenarios:
- crowdsecurity/ssh-bf

Current metrics : 

 - (Scenario) crowdsecurity/ssh-bf: 
+---------------+-----------+--------------+--------+---------+
| CURRENT COUNT | OVERFLOWS | INSTANCIATED | POURED | EXPIRED |
+---------------+-----------+--------------+--------+---------+
|             0 |         1 |            2 |     10 |       1 |
+---------------+-----------+--------------+--------+---------+

```

<details>