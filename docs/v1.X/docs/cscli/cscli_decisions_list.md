## cscli decisions list

List decisions from LAPI

```
cscli decisions list [options] [flags]
```

### Examples

```
cscli decisions list -i 1.2.3.4
cscli decisions list -r 1.2.3.0/24
cscli decisions list -s crowdsecurity/ssh-bf
cscli decisions list -t ban

```

### Options

```
  -a, --all               Include decisions from Central API
      --since string      restrict to alerts newer than since (ie. 4h, 30d)
      --until string      restrict to alerts older than until (ie. 4h, 30d)
  -t, --type string       restrict to this decision type (ie. ban,captcha)
      --scope string      restrict to this scope (ie. ip,range,session)
  -v, --value string      restrict to this value (ie. 1.2.3.4,userName)
  -s, --scenario string   restrict to this scenario (ie. crowdsecurity/ssh-bf)
  -i, --ip string         restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)
  -r, --range string      restrict to alerts from this source range (shorthand for --scope range --value <RANGE>)
      --no-simu           exclude decisions in simulation mode
      --contained         query decisions contained by range
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

* [cscli decisions](cscli_decisions.md)	 - Manage decisions


