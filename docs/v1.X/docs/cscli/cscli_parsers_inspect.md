## cscli parsers inspect

Inspect given parser

### Synopsis

Inspect given parser

```
cscli parsers inspect [name] [flags]
```

### Examples

```
cscli parsers inspect crowdsec/xxx
```

### Options

```
  -h, --help         help for inspect
  -u, --url string   Prometheus url
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


