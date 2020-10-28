## cscli ban flush

Fush ban DB

### Synopsis

Fush ban DB

```
cscli ban flush [flags]
```

### Examples

```
cscli ban flush
```

### Options

```
  -h, --help   help for flush
```

### Options inherited from parent commands

```
  -c, --config string        path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug                Set logging to debug.
      --error                Set logging to error.
      --info                 Set logging to info.
  -o, --output string        Output format : human, json, raw. (default "human")
      --remediation string   Set specific remediation type : ban|slow|captcha (default "ban")
      --warning              Set logging to warning.
```

### SEE ALSO

* [cscli ban](cscli_ban.md)	 - Manage bans/mitigations


