## cscli install postoverflow

Install given postoverflow parser

### Synopsis

Fetch and install given postoverflow from hub.
As a reminder, postoverflows are parsing configuration that will occur after the overflow (before a decision is applied).

```
cscli install postoverflow [config] [flags]
```

### Examples

```
cscli install collection crowdsec/xxx
```

### Options

```
  -h, --help   help for postoverflow
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
  -d, --download-only   Only download packages, don't enable
      --error           Set logging to error.
      --force           Force install : Overwrite tainted and outdated files
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli install](cscli_install.md)	 - Install configuration(s) from hub


