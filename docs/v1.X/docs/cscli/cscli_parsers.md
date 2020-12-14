## cscli parsers

Install/Remove/Upgrade/Inspect parser(s) from hub

### Examples

```
cscli parsers install crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/sshd-logs
cscli parsers list
cscli parsers remove crowdsecurity/sshd-logs

```

### Options

```
  -h, --help   help for parsers
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

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli parsers inspect](cscli_parsers_inspect.md)	 - Inspect given parser
* [cscli parsers install](cscli_parsers_install.md)	 - Install given parser(s)
* [cscli parsers list](cscli_parsers_list.md)	 - List all parsers or given one
* [cscli parsers remove](cscli_parsers_remove.md)	 - Remove given parser(s)
* [cscli parsers upgrade](cscli_parsers_upgrade.md)	 - Upgrade given parser(s)


