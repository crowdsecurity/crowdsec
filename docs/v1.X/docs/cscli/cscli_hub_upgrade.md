## cscli hub upgrade

Upgrade all configs installed from hub

### Synopsis


Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.


```
cscli hub upgrade [flags]
```

### Options

```
      --force   Force upgrade : Overwrite tainted and outdated files
  -h, --help    help for upgrade
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


