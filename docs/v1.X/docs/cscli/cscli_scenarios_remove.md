## cscli scenarios remove

Remove given scenario(s)

### Synopsis

remove given scenario(s)

```
cscli scenarios remove [config] [flags]
```

### Examples

```
cscli scenarios remove crowdsec/xxx crowdsec/xyz
```

### Options

```
      --all     Delete all the scenarios
      --force   Force remove : Remove tainted and outdated files
  -h, --help    help for remove
      --purge   Delete source file too
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


