## cscli api enroll

Associate your machine to an existing crowdsec user

### Synopsis

Enrolling your machine into your user account will allow for more accurate lists and threat detection. See website to create user account.

```
cscli api enroll [flags]
```

### Examples

```
cscli api enroll -u 1234567890ffff
```

### Options

```
  -h, --help          help for enroll
  -u, --user string   User ID (required)
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

* [cscli api](cscli_api.md)	 - Crowdsec API interaction


