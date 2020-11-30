{{v0X.cli.bin}} allows you install, list, upgrade and remove configurations : parsers, enrichment, scenarios.

!!! warning
    If you're not running the latest CrowdSec version, configurations might not be the latest available. `cscli` will use the branch of the corresponding CrowdSec version to download and install configurations from the hub (it will use the `master` branch if you are on the latest CrowdSec version). 

The various parsers, enrichers and scenarios installed on your machine makes a coherent ensemble to provide detection capabilities.

_Parsers, Scenarios and Enrichers are often bundled together in "collections" to facilitate configuration._

Parsers, scenarios, enrichers and collections all follow the same principle :

 - `{{v0X.cli.bin}} install parser crowdsec/nginx-logs`
 - `{{v0X.cli.bin}} update collection crowdsec/base-http-scenarios`
 - `{{v0X.cli.bin}} remove scenario crowdsec/mysql-bf`

> Please see your local `{{v0X.cli.bin}} help` for up-to-date documentation


## List configurations

```
{{v0X.cli.bin}} list
```

**note** `-a` allows for listing of uninstalled configurations as well

<details>
  <summary>{{v0X.cli.name}} list example</summary>

```bash
$ {{v0X.cli.bin}} list
INFO[0000] Loaded 9 collecs, 14 parsers, 12 scenarios, 1 post-overflow parsers 
INFO[0000] PARSERS:                                     
--------------------------------------------------------------------------------------------------------------------
 NAME                       📦 STATUS    VERSION  LOCAL PATH                                                        
--------------------------------------------------------------------------------------------------------------------
 crowdsec/nginx-logs        ✔️  enabled  0.3      /etc/crowdsec/config/parsers/s01-parse/nginx-logs.yaml        
 crowdsec/geoip-enrich      ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/geoip-enrich.yaml     
 crowdsec/syslog-logs       ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml         
 crowdsec/whitelists        ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/whitelists.yaml       
 crowdsec/http-logs         ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/http-logs.yaml        
 crowdsec/dateparse-enrich  ✔️  enabled  0.4      /etc/crowdsec/config/parsers/s02-enrich/dateparse-enrich.yaml 
--------------------------------------------------------------------------------------------------------------------
INFO[0000] SCENARIOS:                                   
-----------------------------------------------------------------------------------------------------------------------
 NAME                             📦 STATUS    VERSION  LOCAL PATH                                                     
-----------------------------------------------------------------------------------------------------------------------
 crowdsec/http-scan-uniques_404   ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-scan-uniques_404.yaml  
 crowdsec/http-crawl-non_statics  ✔️  enabled  0.4      /etc/crowdsec/config/scenarios/http-crawl-non_statics.yaml 
-----------------------------------------------------------------------------------------------------------------------
INFO[0000] COLLECTIONS:                                 
-------------------------------------------------------------------------------------------------------------------
 NAME                          📦 STATUS    VERSION  LOCAL PATH                                                    
-------------------------------------------------------------------------------------------------------------------
 crowdsec/linux                ✔️  enabled  0.2      /etc/crowdsec/config/collections/linux.yaml               
 crowdsec/nginx                ✔️  enabled  0.2      /etc/crowdsec/config/collections/nginx.yaml               
 crowdsec/base-http-scenarios  ✔️  enabled  0.1      /etc/crowdsec/config/collections/base-http-scenarios.yaml 
-------------------------------------------------------------------------------------------------------------------
INFO[0000] POSTOVERFLOWS:                               
--------------------------------------
 NAME  📦 STATUS  VERSION  LOCAL PATH 
--------------------------------------
--------------------------------------

```
</details>



For {{v0X.parsers.htmlname}}, {{v0X.scenarios.htmlname}}, {{v0X.collections.htmlname}} the outputs include, beside the version, the path and the name, a `STATUS` column :

 - `✔️  enabled` : configuration is up-to-date
 - `⚠️  enabled,outdated` : a newer version is available
 - `🚫  enabled,local` : configuration is not managed by {{v0X.cli.name}}
 - `⚠️  enabled,tainted` : configuration has been locally modified

(see `{{v0X.cli.name}} upgrade` to upgrade/sync your configurations with {{v0X.hub.htmlname}})

## Install new configurations


`{{v0X.cli.bin}} install parser|scenario|postoverflow <name> [--force]`


  - `{{v0X.cli.bin}} install parser crowdsec/nginx-logs`
  - `{{v0X.cli.bin}} install scenario crowdsec/http-scan-uniques_404`


## Remove configurations


`{{v0X.cli.bin}} remove parser|scenario|postoverflow <name> [--force]`


## Upgrade configurations

> upgrade a specific scenario

```
{{v0X.cli.bin}} upgrade scenario crowdsec/http-scan-uniques_404
```


> upgrade **all** scenarios

```
{{v0X.cli.bin}} upgrade scenario --all
```

> upgrade **all** configurations (parsers, scenarios, collections, postoverflows)

```
{{v0X.cli.bin}} upgrade --all
```

