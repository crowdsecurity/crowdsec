## cscli config

Allows to view/edit cscli config

### Synopsis

Allow to configure database plugin path and installation directory.
If no commands are specified, config is in interactive mode.

### Examples

```
 - cscli config show
- cscli config prompt
```

### Options

```
  -h, --help   help for config
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
* [cscli config show](cscli_config_show.md)	 - Displays current config


