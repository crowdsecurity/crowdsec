## cscli parsers install

Install given parser(s)

### Synopsis

Fetch and install given parser(s) from hub

```
cscli parsers install [config] [flags]
```

### Examples

```
cscli parsers install crowdsec/xxx crowdsec/xyz
```

### Options

```
  -d, --download-only   Only download packages, don't enable
      --force           Force install : Overwrite tainted and outdated files
  -h, --help            help for install
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

* [cscli parsers](cscli_parsers.md)	 - Install/Remove/Upgrade/Inspect parser(s) from hub


