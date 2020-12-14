## cscli postoverflows install

Install given postoverflow(s)

### Synopsis

Fetch and install given postoverflow(s) from hub

```
cscli postoverflows install [config] [flags]
```

### Examples

```
cscli postoverflows install crowdsec/xxx crowdsec/xyz
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

* [cscli postoverflows](cscli_postoverflows.md)	 - Install/Remove/Upgrade/Inspect postoverflow(s) from hub


