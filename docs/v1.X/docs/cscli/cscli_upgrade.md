## cscli upgrade

Upgrade configuration(s)

### Synopsis


Upgrade configuration from the CrowdSec Hub.

In order to upgrade latest versions of configuration, 
the Hub cache should be [updated](./cscli_update.md).
 
Tainted configuration will not be updated (use --force to update them).

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
 

 

```
cscli upgrade [type] [config] [flags]
```

### Examples

```
cscli upgrade [type] [config_name]
cscli upgrade --all   # Upgrade all configurations types
cscli upgrade --force # Overwrite tainted configuration
		
```

### Options

```
      --all     Upgrade all configuration in scope
      --force   Overwrite existing files, even if tainted
  -h, --help    help for upgrade
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli upgrade collection](cscli_upgrade_collection.md)	 - Upgrade collection configuration(s)
* [cscli upgrade parser](cscli_upgrade_parser.md)	 - Upgrade parser configuration(s)
* [cscli upgrade postoverflow](cscli_upgrade_postoverflow.md)	 - Upgrade postoverflow parser configuration(s)
* [cscli upgrade scenario](cscli_upgrade_scenario.md)	 - Upgrade scenario configuration(s)


