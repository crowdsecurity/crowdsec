## cscli ban del range

Delete bans for given ip from db

### Synopsis

Delete bans for given ip from db

```
cscli ban del range <target> [flags]
```

### Examples

```
cscli ban del range 1.2.3.0/24
```

### Options

```
  -h, --help   help for range
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

* [cscli ban del](cscli_ban_del.md)	 - Delete bans from db


