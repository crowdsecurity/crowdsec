## cscli backup restore

Restore configuration (api, parsers, scenarios etc.) from directory

### Synopsis

restore command will try to restore all saved information from <directory> to yor local setup, including :

- Installation of up-to-date scenarios/parsers/... via cscli

- Restauration of tainted/local/out-of-date scenarios/parsers/... file

- Restauration of API credentials (if the existing ones aren't working)

- Restauration of acqusition configuration


```
cscli backup restore <directory> [flags]
```

### Examples

```
cscli backup restore ./my-backup
```

### Options

```
  -h, --help   help for restore
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

* [cscli backup](cscli_backup.md)	 - Backup or restore configuration (api, parsers, scenarios etc.) to/from directory


