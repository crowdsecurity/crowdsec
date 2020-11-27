## cscli ban del

Delete bans from db

### Synopsis

The removal of the bans can be applied on a single IP address or directly on a IP range.

### Examples

```
cscli ban del ip 1.2.3.4  
cscli ban del range 1.2.3.0/24
```

### Options

```
  -h, --help   help for del
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
* [cscli ban del ip](cscli_ban_del_ip.md)	 - Delete bans for given ip from db
* [cscli ban del range](cscli_ban_del_range.md)	 - Delete bans for given ip from db


