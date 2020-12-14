## cscli alerts inspect

Show info about an alert

```
cscli alerts inspect <alert_id> [flags]
```

### Examples

```
cscli alerts inspect 123
```

### Options

```
  -d, --details   show alerts with events
  -h, --help      help for inspect
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

* [cscli alerts](cscli_alerts.md)	 - Manage alerts


