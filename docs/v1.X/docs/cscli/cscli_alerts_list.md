## cscli alerts list

List alerts

```
cscli alerts list [filters] [flags]
```

### Examples

```
cscli alerts list
cscli alerts list --ip 1.2.3.4
cscli alerts list --range 1.2.3.0/24
cscli alerts list -s crowdsecurity/ssh-bf
cscli alerts list --type ban
```

### Options

```
      --until string      restrict to alerts older than until (ie. 4h, 30d)
      --since string      restrict to alerts newer than since (ie. 4h, 30d)
  -i, --ip string         restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)
  -s, --scenario string   the scenario (ie. crowdsecurity/ssh-bf)
  -r, --range string      restrict to alerts from this range (shorthand for --scope range --value <RANGE/X>)
      --type string       restrict to alerts with given decision type (ie. ban, captcha)
      --scope string      restrict to alerts of this scope (ie. ip,range)
  -v, --value string      the value to match for in the specified scope
      --contained         query decisions contained by range
  -m, --machine           print machines that sended alerts
  -l, --limit int         limit size of alerts list table (0 to view all alerts) (default 50)
  -h, --help              help for list
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


