## cscli machines delete

delete machines

```
cscli machines delete --machine MyTestMachine [flags]
```

### Examples

```
cscli machines delete <machine_name>
```

### Options

```
  -h, --help             help for delete
  -m, --machine string   machine to delete
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

* [cscli machines](cscli_machines.md)	 - Manage local API machines [requires local API]


