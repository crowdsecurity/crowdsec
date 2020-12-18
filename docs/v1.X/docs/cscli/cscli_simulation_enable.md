## cscli simulation enable

Enable the simulation, globally or on specified scenarios

```
cscli simulation enable [scenario] [-global] [flags]
```

### Examples

```
cscli simulation enable
```

### Options

```
  -g, --global   Enable global simulation (reverse mode)
  -h, --help     help for enable
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw.
      --trace           Set logging to trace.
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli simulation](cscli_simulation.md)	 - Manage simulation status of scenarios


