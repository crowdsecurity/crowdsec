## cscli postoverflows upgrade

Upgrade given postoverflow(s)

### Synopsis

Fetch and Upgrade given postoverflow(s) from hub

```
cscli postoverflows upgrade [config] [flags]
```

### Examples

```
cscli postoverflows upgrade crowdsec/xxx crowdsec/xyz
```

### Options

```
  -a, --all     Upgrade all the postoverflows
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

* [cscli postoverflows](cscli_postoverflows.md)	 - Install/Remove/Upgrade/Inspect postoverflow(s) from hub


