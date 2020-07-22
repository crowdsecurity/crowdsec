## cscli ban add

Adds a ban against a given ip/range for the provided duration

### Synopsis


Allows to add a ban against a specific ip or range target for a specific duration.  

The duration argument can be expressed in seconds(s), minutes(m) or hours (h).
		
See [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) for more informations.

### Examples

```
cscli ban add ip 1.2.3.4 24h "scan"  
cscli ban add range 1.2.3.0/24 24h "the whole range"
```

### Options

```
  -h, --help   help for add
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
* [cscli ban add ip](cscli_ban_add_ip.md)	 - Adds the specific ip to the ban db
* [cscli ban add range](cscli_ban_add_range.md)	 - Adds the specific ip to the ban db


