## cscli postoverflows remove

Remove given postoverflow(s)

### Synopsis

remove given postoverflow(s)

```
cscli postoverflows remove [config] [flags]
```

### Examples

```
cscli postoverflows remove crowdsec/xxx crowdsec/xyz
```

### Options

```
      --all     Delete all the postoverflows
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

* [cscli postoverflows](cscli_postoverflows.md)	 - Install/Remove/Upgrade/Inspect postoverflow(s) from hub


