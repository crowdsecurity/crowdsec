## cscli remove

Remove/disable configuration(s)

### Synopsis


 Remove local configuration. 
 
[type] must be parser, scenario, postoverflow, collection

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net) or locally installed.
 

### Examples

```
cscli remove [type] [config_name]
```

### Options

```
      --all     Delete all the files in selected scope
  -h, --help    help for remove
      --purge   Delete source file in ~/.cscli/hub/ too
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
* [cscli remove collection](cscli_remove_collection.md)	 - Remove/disable collection
* [cscli remove parser](cscli_remove_parser.md)	 - Remove/disable parser
* [cscli remove postoverflow](cscli_remove_postoverflow.md)	 - Remove/disable postoverflow parser
* [cscli remove scenario](cscli_remove_scenario.md)	 - Remove/disable scenario


