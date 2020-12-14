## cscli config restore

Restore config in backup <directory>

### Synopsis

Restore the crowdsec configuration from specified backup <directory> including:

- Main config (config.yaml)
- Simulation config (simulation.yaml)
- Profiles config (profiles.yaml)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Backup of API credentials (local API and online API)

```
cscli config restore <directory> [flags]
```

### Options

```
  -h, --help         help for restore
      --old-backup   To use when you are upgrading crowdsec v0.X to v1.X and you need to restore backup from v0.X
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw.
      --trace           Set logging to trace.
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli config](cscli_config.md)	 - Allows to view current config


