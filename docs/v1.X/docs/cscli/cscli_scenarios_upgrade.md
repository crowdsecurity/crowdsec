## cscli scenarios upgrade

Upgrade given scenario(s)

### Synopsis

Fetch and Upgrade given scenario(s) from hub

```
cscli scenarios upgrade [config] [flags]
```

### Examples

```
cscli scenarios upgrade crowdsec/xxx crowdsec/xyz
```

### Options

```
  -a, --all     Upgrade all the scenarios
      --force   Force upgrade : Overwrite tainted and outdated files
  -h, --help    help for upgrade
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

* [cscli scenarios](cscli_scenarios.md)	 - Install/Remove/Upgrade/Inspect scenario(s) from hub


