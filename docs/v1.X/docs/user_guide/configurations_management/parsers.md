{{v1X.hub.htmlname}} allows you to find needed parsers.

## Installing parsers

```bash
$ sudo cscli parsers install crowdsecurity/sshd-logs
```

<details>
  <summary>cscli parsers install example</summary>

```bash
$ sudo cscli parsers install crowdsecurity/iptables-logs    
INFO[0000] crowdsecurity/iptables-logs : OK             
INFO[0000] Enabled parsers : crowdsecurity/iptables-logs 
INFO[0000] Enabled crowdsecurity/iptables-logs          
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
```
</details>

## Listing installed parsers

```bash
sudo cscli parsers list
```

{{v1X.parsers.Htmlname}} are yaml files in `{{v1X.config.crowdsec_dir}}parsers/<STAGE>/parser.yaml`.


<details>
  <summary>cscli parsers list example</summary>

```bash
$ sudo cscli parsers list
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
$ sudo {{v1X.cli.bin}} parsers upgrade crowdsecurity/sshd-logs
```

Parsers upgrade allows you to upgrade an existing parser to the latest version.

<details>
  <summary>cscli parsers upgrade example</summary>

```bash
$ sudo cscli parsers upgrade crowdsecurity/sshd-logs  
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
$ sudo cscli parsers inspect crowdsecurity/sshd-logs 
```

Parsers inspect will give you detailed information about a given parser, including versioning information *and* runtime metrics (fetched from prometheus).

<!--TBD: refaire l'output apres avoir fix le 'parsers inspect XXXX'-->
<details>
  <summary>cscli parsers inspect example</summary>

```bash
$ sudo cscli parsers inspect crowdsecurity/sshd-logs     
type: parsers
stage: s01-parse
name: crowdsecurity/sshd-logs
filename: sshd-logs.yaml
description: Parse openSSH logs
author: crowdsecurity
belongs_to_collections:
- crowdsecurity/sshd
remote_path: parsers/s01-parse/crowdsecurity/sshd-logs.yaml
version: "0.1"
local_path: /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml
localversion: "0.1"
localhash: ecd40cb8cd95e2bad398824ab67b479362cdbf0e1598b8833e2f537ae3ce2f93
installed: true
downloaded: true
uptodate: true
tainted: false
local: false

Current metrics :

 - (Parser) crowdsecurity/sshd-logs:
+-------------------+-------+--------+----------+
|      PARSERS      | HITS  | PARSED | UNPARSED |
+-------------------+-------+--------+----------+
| /var/log/auth.log | 94138 |  42404 |    51734 |
+-------------------+-------+--------+----------+

```

<details>

## Reference documentation

[Link to parsers reference documentation](/Crowdsec/v1/references/parsers/)

