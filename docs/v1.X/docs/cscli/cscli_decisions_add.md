## cscli decisions add

Add decision to LAPI

```
cscli decisions add [options] [flags]
```

### Examples

```
cscli decisions add --ip 1.2.3.4
cscli decisions add --range 1.2.3.0/24
cscli decisions add --ip 1.2.3.4 --duration 24h --type captcha
cscli decisions add --scope username --value foobar

```

### Options

```
  -i, --ip string         Source ip (shorthand for --scope ip --value <IP>)
  -r, --range string      Range source ip (shorthand for --scope range --value <RANGE>)
  -d, --duration string   Decision duration (ie. 1h,4h,30m) (default "4h")
  -v, --value string      The value (ie. --scope username --value foobar)
      --scope string      Decision scope (ie. ip,range,username) (default "Ip")
  -R, --reason string     Decision reason (ie. scenario-name)
  -t, --type string       Decision type (ie. ban,captcha,throttle) (default "ban")
  -h, --help              help for add
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


