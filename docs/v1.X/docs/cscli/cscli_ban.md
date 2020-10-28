## cscli ban

Manage bans/mitigations

### Synopsis

This is the main interaction point with local ban database for humans.

You can add/delete/list or flush current bans in your local ban DB.

### Options

```
      --remediation string   Set specific remediation type : ban|slow|captcha (default "ban")
  -h, --help                 help for ban
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli ban add](cscli_ban_add.md)	 - Adds a ban against a given ip/range for the provided duration
* [cscli ban del](cscli_ban_del.md)	 - Delete bans from db
* [cscli ban flush](cscli_ban_flush.md)	 - Fush ban DB
* [cscli ban list](cscli_ban_list.md)	 - List local or api bans/remediations


