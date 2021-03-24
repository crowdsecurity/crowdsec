## cscli decisions delete

Delete decisions

```
cscli decisions delete [options] [flags]
```

### Examples

```
cscli decisions delete -r 1.2.3.0/24
cscli decisions delete -i 1.2.3.4
cscli decisions delete -s crowdsecurity/ssh-bf
cscli decisions delete --id 42
cscli decisions delete --type captcha

```

### Options

```
  -i, --ip string      Source ip (shorthand for --scope ip --value <IP>)
  -r, --range string   Range source ip (shorthand for --scope range --value <RANGE>)
      --id string      decision id
  -t, --type string    the decision type (ie. ban,captcha)
  -v, --value string   the value to match for in the specified scope
      --all            delete all decisions
      --contained      query decisions contained by range
  -h, --help           help for delete
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


