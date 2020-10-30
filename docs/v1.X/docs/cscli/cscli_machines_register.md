## cscli machines register

register a machine to a remote API

### Synopsis

register a machine to a remote API.
/!\ The machine will not be validated. You have to connect on the remote API server and run 'cscli machine validate -m <machine_id>'

```
cscli machines register -u http://127.0.0.1:8080/ [flags]
```

### Examples

```
cscli machine register
```

### Options

```
  -f, --file string   output file destination
  -h, --help          help for register
  -u, --url string    URL of the API
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

* [cscli machines](cscli_machines.md)	 - Manage local API machines


