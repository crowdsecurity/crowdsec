## cscli

cscli allows you to manage crowdsec

### Synopsis

cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.

### Examples

```
View/Add/Remove bans:  
 - cscli ban list  
 - cscli ban add ip 1.2.3.4 24h 'go away'  
 - cscli ban del 1.2.3.4  
		
View/Add/Upgrade/Remove scenarios and parsers:  
 - cscli list  
 - cscli install collection crowdsec/linux-web  
 - cscli remove scenario crowdsec/ssh_enum  
 - cscli upgrade --all  

API interaction:
 - cscli api pull
 - cscli api register
 
```

### Options

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
  -o, --output string   Output format : human, json, raw. (default "human")
      --debug           Set logging to debug.
      --info            Set logging to info.
      --warning         Set logging to warning.
      --error           Set logging to error.
  -h, --help            help for cscli
```

### SEE ALSO

* [cscli api](cscli_api.md)	 - Crowdsec API interaction
* [cscli backup](cscli_backup.md)	 - Backup or restore configuration (api, parsers, scenarios etc.) to/from directory
* [cscli ban](cscli_ban.md)	 - Manage bans/mitigations
* [cscli config](cscli_config.md)	 - Allows to view/edit cscli config
* [cscli dashboard](cscli_dashboard.md)	 - Start a dashboard (metabase) container.
* [cscli inspect](cscli_inspect.md)	 - Inspect configuration(s)
* [cscli install](cscli_install.md)	 - Install configuration(s) from hub
* [cscli list](cscli_list.md)	 - List enabled configs
* [cscli metrics](cscli_metrics.md)	 - Display crowdsec prometheus metrics.
* [cscli remove](cscli_remove.md)	 - Remove/disable configuration(s)
* [cscli simulation](cscli_simulation.md)	 - 
* [cscli update](cscli_update.md)	 - Fetch available configs from hub
* [cscli upgrade](cscli_upgrade.md)	 - Upgrade configuration(s)


