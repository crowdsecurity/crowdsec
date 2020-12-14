## cscli config backup

Backup current config

### Synopsis

Backup the current crowdsec configuration including :

- Main config (config.yaml)
- Simulation config (simulation.yaml)
- Profiles config (profiles.yaml)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Backup of API credentials (local API and online API)

```
cscli config backup <directory> [flags]
```

### Examples

```
cscli config backup ./my-backup
```

### Options

```
  -h, --help   help for backup
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


