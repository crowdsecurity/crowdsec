## cscli backup

Backup or restore configuration (api, parsers, scenarios etc.) to/from directory

### Synopsis

This command is here to help you save and/or restore crowdsec configurations to simple replication

### Examples

```
cscli backup save ./my-backup
cscli backup restore ./my-backup
```

### Options

```
  -h, --help   help for backup
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
* [cscli backup restore](cscli_backup_restore.md)	 - Restore configuration (api, parsers, scenarios etc.) from directory
* [cscli backup save](cscli_backup_save.md)	 - Backup configuration (api, parsers, scenarios etc.) to directory


