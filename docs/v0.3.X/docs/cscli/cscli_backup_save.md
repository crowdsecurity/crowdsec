## cscli backup save

Backup configuration (api, parsers, scenarios etc.) to directory

### Synopsis

backup command will try to save all relevant informations to crowdsec config, including :

- List of scenarios, parsers, postoverflows and collections that are up-to-date

- Actual backup of tainted/local/out-of-date scenarios, parsers, postoverflows and collections

- Backup of API credentials

- Backup of acquisition configuration
		
		

```
cscli backup save <directory> [flags]
```

### Examples

```
cscli backup save ./my-backup
```

### Options

```
  -h, --help   help for save
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


