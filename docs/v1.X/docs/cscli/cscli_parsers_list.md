## cscli parsers list

List all parsers or given one

### Synopsis

List all parsers or given one

```
cscli parsers list [name] [flags]
```

### Examples

```
cscli parsers list
cscli parser list crowdsecurity/xxx
```

### Options

```
  -a, --all    List as well disabled items
  -h, --help   help for list
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


