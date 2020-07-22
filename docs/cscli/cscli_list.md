## cscli list

List enabled configs

### Synopsis


List enabled configurations (parser/scenarios/collections) on your host.

It is possible to list also configuration from [Crowdsec Hub](https://hub.crowdsec.net) with the '-a' options.

[type] must be parsers, scenarios, postoverflows, collections
		

```
cscli list [-a] [flags]
```

### Examples

```
cscli list  # List all local configurations
cscli list [type] # List all local configuration of type [type]
cscli list -a # List all local and remote configurations
		
```

### Options

```
  -a, --all    List as well disabled items
  -h, --help   help for list
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
* [cscli list collections](cscli_list_collections.md)	 - List enabled collections
* [cscli list parsers](cscli_list_parsers.md)	 - List enabled parsers
* [cscli list postoverflows](cscli_list_postoverflows.md)	 - List enabled postoverflow parsers
* [cscli list scenarios](cscli_list_scenarios.md)	 - List enabled scenarios


