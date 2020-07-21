## cscli api pull

Pull crowdsec API TopX

### Synopsis

Pulls a list of malveolent IPs relevant to your situation and add them into the local ban database.

```
cscli api pull [flags]
```

### Examples

```
cscli api pull
```

### Options

```
  -h, --help   help for pull
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


