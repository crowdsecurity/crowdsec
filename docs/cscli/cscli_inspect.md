## cscli inspect

Inspect configuration(s)

### Synopsis


Inspect give you full detail about local installed configuration.

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net) or locally installed.


### Examples

```
cscli inspect parser crowdsec/xxx  
cscli inspect collection crowdsec/xxx
```

### Options

```
  -h, --help   help for inspect
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
* [cscli inspect collection](cscli_inspect_collection.md)	 - Inspect given collection
* [cscli inspect parser](cscli_inspect_parser.md)	 - Inspect given log parser
* [cscli inspect postoverflow](cscli_inspect_postoverflow.md)	 - Inspect given postoverflow parser
* [cscli inspect scenario](cscli_inspect_scenario.md)	 - Inspect given scenario


