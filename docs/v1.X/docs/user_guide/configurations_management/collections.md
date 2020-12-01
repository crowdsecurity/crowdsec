
{{v1X.hub.htmlname}} allows you to find needed collections.

## Installing collections

```bash
$ sudo cscli collections install crowdsecurity/whitelist-good-actors
```

<details>
  <summary>{{v1X.cli.name}} collection install example</summary>

```bash
$ sudo cscli collections install crowdsecurity/whitelist-good-actors
INFO[0000] crowdsecurity/seo-bots-whitelist : OK        
INFO[0000] downloading data 'https://raw.githubusercontent.com/crowdsecurity/sec-lists/master/whitelists/benign_bots/search_engine_crawlers/rdns_seo_bots.txt' in '/var/lib/crowdsec/data/rdns_seo_bots.txt' 
INFO[0001] downloading data 'https://raw.githubusercontent.com/crowdsecurity/sec-lists/master/whitelists/benign_bots/search_engine_crawlers/rnds_seo_bots.regex' in '/var/lib/crowdsec/data/rdns_seo_bots.regex' 
INFO[0002] downloading data 'https://raw.githubusercontent.com/crowdsecurity/sec-lists/master/whitelists/benign_bots/search_engine_crawlers/ip_seo_bots.txt' in '/var/lib/crowdsec/data/ip_seo_bots.txt' 
INFO[0002] crowdsecurity/cdn-whitelist : OK             
INFO[0002] downloading data 'https://www.cloudflare.com/ips-v4' in '/var/lib/crowdsec/data/cloudflare_ips.txt' 
INFO[0003] crowdsecurity/rdns : OK                      
INFO[0003] crowdsecurity/whitelist-good-actors : OK     
INFO[0003] /etc/crowdsec/postoverflows/s01-whitelist doesn't exist, create 
INFO[0003] Enabled postoverflows : crowdsecurity/seo-bots-whitelist 
INFO[0003] Enabled postoverflows : crowdsecurity/cdn-whitelist 
INFO[0003] /etc/crowdsec/postoverflows/s00-enrich doesn't exist, create 
INFO[0003] Enabled postoverflows : crowdsecurity/rdns   
INFO[0003] Enabled collections : crowdsecurity/whitelist-good-actors 
INFO[0003] Enabled crowdsecurity/whitelist-good-actors  
INFO[0003] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
$ systemctl reload crowdsec
```
</details>


## Listing installed collections

```bash
$ sudo {{v1X.cli.bin}} collections list
```

<details>
  <summary>cscli collections list example</summary>

```bash
$ sudo cscli collections list   
-------------------------------------------------------------------------------------------------------------
 NAME                               📦 STATUS    VERSION  LOCAL PATH                                         
-------------------------------------------------------------------------------------------------------------
 crowdsecurity/nginx                ✔️  enabled  0.1      /etc/crowdsec/collections/nginx.yaml               
 crowdsecurity/base-http-scenarios  ✔️  enabled  0.1      /etc/crowdsec/collections/base-http-scenarios.yaml 
 crowdsecurity/sshd                 ✔️  enabled  0.1      /etc/crowdsec/collections/sshd.yaml                
 crowdsecurity/linux                ✔️  enabled  0.2      /etc/crowdsec/collections/linux.yaml               
-------------------------------------------------------------------------------------------------------------
```

</details>

## Upgrading installed collections

```bash
$ sudo {{v1X.cli.bin}} hub update
$ sudo {{v1X.cli.bin}} collections upgrade crowdsecurity/sshd
```

Collection upgrade allows you to upgrade an existing collection (and its items) to the latest version.


<details>
  <summary>cscli collections upgrade example</summary>

```bash
$ sudo cscli collections upgrade crowdsecurity/sshd  
INFO[0000] crowdsecurity/sshd : up-to-date              
WARN[0000] crowdsecurity/sshd-logs : overwrite          
WARN[0000] crowdsecurity/ssh-bf : overwrite             
WARN[0000] crowdsecurity/sshd : overwrite               
INFO[0000] 📦 crowdsecurity/sshd : updated               
INFO[0000] Upgraded 1 items                             
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective.
$ systemctl reload crowdsec

```

</details>

## Monitoring collections

```bash
$ sudo cscli collections inspect crowdsecurity/sshd
```

Collections inspect will give you detailed information about a given collection, including versioning information *and* runtime metrics (fetched from prometheus).

<details>
  <summary>cscli collections inspect example</summary>

```bash
$ sudo cscli collections inspect crowdsecurity/sshd       
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

</details>

## Reference documentation

[Link to collections reference documentation](/Crowdsec/v1/references/collections/)
