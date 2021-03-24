## cscli alerts delete

Delete alerts
/!\ This command can be use only on the same machine than the local API.

```
cscli alerts delete [filters] [--all] [flags]
```

### Examples

```
cscli alerts delete --ip 1.2.3.4
cscli alerts delete --range 1.2.3.0/24
cscli alerts delete -s crowdsecurity/ssh-bf"
```

### Options

```
      --scope string      the scope (ie. ip,range)
  -v, --value string      the value to match for in the specified scope
  -s, --scenario string   the scenario (ie. crowdsecurity/ssh-bf)
  -i, --ip string         Source ip (shorthand for --scope ip --value <IP>)
  -r, --range string      Range source ip (shorthand for --scope range --value <RANGE>)
  -a, --all               delete all alerts
      --contained         query decisions contained by range
  -h, --help              help for delete
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


