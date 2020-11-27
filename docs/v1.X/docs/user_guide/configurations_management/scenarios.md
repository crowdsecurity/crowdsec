{{v1X.hub.htmlname}} allows you to find needed scenarios.

## Installing scenarios

```bash
$ cscli scenarios install crowdsecurity/http-bf-wordpress_bf
```

<details>
  <summary>cscli scenarios install example</summary>

```bash
$ cscli scenarios install crowdsecurity/http-bf-wordpress_bf
INFO[0000] crowdsecurity/http-bf-wordpress_bf : OK      
INFO[0000] Enabled scenarios : crowdsecurity/http-bf-wordpress_bf 
INFO[0000] Enabled crowdsecurity/http-bf-wordpress_bf   
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
$ systemctl reload crowdsec
```

</details>


## Listing installed scenarios

```bash
cscli scenarios list
```

{{v1X.scenarios.Htmlname}} are yaml files in `{{v1X.config.crowdsec_dir}}scenarios/`.


<details>
  <summary>cscli scenarios list example</summary>

```bash
$ cscli scenarios list
---------------------------------------------------------------------------------------------------------------------------
 NAME                                       📦 STATUS    VERSION  LOCAL PATH                                               
---------------------------------------------------------------------------------------------------------------------------
 crowdsecurity/ssh-bf                       ✔️  enabled  0.1      /etc/crowdsec/scenarios/ssh-bf.yaml                      
 crowdsecurity/http-bf-wordpress_bf         ✔️  enabled  0.1      /etc/crowdsec/scenarios/http-bf-wordpress_bf.yaml        
 crowdsecurity/http-crawl-non_statics       ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-crawl-non_statics.yaml      
 crowdsecurity/http-probing                 ✔️  enabled  0.1      /etc/crowdsec/scenarios/http-probing.yaml                
 crowdsecurity/http-sensitive-files         ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-sensitive-files.yaml        
 crowdsecurity/http-bad-user-agent          ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-bad-user-agent.yaml         
 crowdsecurity/http-path-traversal-probing  ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-path-traversal-probing.yaml 
 crowdsecurity/http-sqli-probing            ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-sqli-probing.yaml           
 crowdsecurity/http-backdoors-attempts      ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-backdoors-attempts.yaml     
 crowdsecurity/http-xss-probing             ✔️  enabled  0.2      /etc/crowdsec/scenarios/http-xss-probing.yaml            
---------------------------------------------------------------------------------------------------------------------------

```

</details>


## Upgrading installed scenarios

```bash
$ cscli scenarios upgrade crowdsecurity/sshd-bf
```

Scenarios upgrade allows you to upgrade an existing scenario to the latest version.

<details>
  <summary>cscli scenarios upgrade example</summary>

```bash
$ cscli scenarios upgrade crowdsecurity/ssh-bf
INFO[0000] crowdsecurity/ssh-bf : up-to-date            
WARN[0000] crowdsecurity/ssh-bf : overwrite             
INFO[0000] 📦 crowdsecurity/ssh-bf : updated             
INFO[0000] Upgraded 1 items                             
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
```

</details>

## Monitoring scenarios

```bash
$ cscli scenarios inspect crowdsecurity/ssh-bf
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

## Reference documentation

[Link to scenarios reference documentation](/Crowdsec/v1/references/scenarios/)
