## cscli ban add range

Adds the specific ip to the ban db

### Synopsis

Duration must be [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) compatible, expressed in s/m/h.

```
cscli ban add range <target> <duration> <reason> [flags]
```

### Examples

```
cscli ban add range 1.2.3.0/24 12h "the whole range"
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

* [cscli ban add](cscli_ban_add.md)	 - Adds a ban against a given ip/range for the provided duration


