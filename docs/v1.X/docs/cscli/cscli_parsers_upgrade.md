## cscli parsers upgrade

Upgrade given parser(s)

### Synopsis

Fetch and upgrade given parser(s) from hub

```
cscli parsers upgrade [config] [flags]
```

### Examples

```
cscli parsers upgrade crowdsec/xxx crowdsec/xyz
```

### Options

```
      --all     Upgrade all the parsers
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

* [cscli parsers](cscli_parsers.md)	 - Install/Remove/Upgrade/Inspect parser(s) from hub


