## cscli hub update

Fetch available configs from hub

### Synopsis


Fetches the [.index.json](https://github.com/crowdsecurity/hub/blob/master/.index.json) file from hub, containing the list of available configs.


```
cscli hub update [flags]
```

### Options

```
  -h, --help   help for update
```

### Options inherited from parent commands

```
  -b, --branch string   Use given branch from hub
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw.
      --trace           Set logging to trace.
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli hub](cscli_hub.md)	 - Manage Hub


