## cscli upgrade scenario

Upgrade scenario configuration(s)

### Synopsis

Upgrade one or more scenario configurations

```
cscli upgrade scenario [config] [flags]
```

### Examples

```
 - cscli	upgrade scenario -all  
 - cscli upgrade scenario crowdsec/http-404 --force  
```

### Options

```
  -h, --help   help for scenario
```

### Options inherited from parent commands

```
      --all             Upgrade all configuration in scope
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --force           Overwrite existing files, even if tainted
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli upgrade](cscli_upgrade.md)	 - Upgrade configuration(s)


