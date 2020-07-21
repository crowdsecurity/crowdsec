## cscli ban list

List local or api bans/remediations

### Synopsis

List the bans, by default only local decisions.

If --all/-a is specified, bans will be displayed without limit (--limit).
Default limit is 50.

Time can be specified with --at and support a variety of date formats:  
 - Jan  2 15:04:05  
 - Mon Jan 02 15:04:05.000000 2006  
 - 2006-01-02T15:04:05Z07:00  
 - 2006/01/02  
 - 2006/01/02 15:04  
 - 2006-01-02  
 - 2006-01-02 15:04


```
cscli ban list [flags]
```

### Examples

```
ban list --range 0.0.0.0/0 : will list all
		ban list --country CN
		ban list --reason crowdsecurity/http-probing
		ban list --as OVH
```

### Options

```
  -a, --all              List bans without limit
      --api              List as well bans received from API
      --as string        List bans belonging to given AS name
      --at string        List bans at given time
      --country string   List bans belonging to given country code
  -h, --help             help for list
      --ip string        List bans for given IP
      --limit int        Limit of bans to display (default 50) (default 50)
      --range string     List bans belonging to given range
      --reason string    List bans containing given reason
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


