## cscli collections upgrade

Upgrade given collection(s)

### Synopsis

Fetch and upgrade given collection(s) from hub

```
cscli collections upgrade collection [flags]
```

### Examples

```
cscli collections upgrade crowdsec/xxx crowdsec/xyz
```

### Options

```
  -a, --all     Upgrade all the collections
      --force   Force upgrade : Overwrite tainted and outdated files
  -h, --help    help for upgrade
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

* [cscli collections](cscli_collections.md)	 - Manage collections from hub


