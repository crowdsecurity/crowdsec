## cscli machines add

add machine to the database.

### Synopsis

Register a new machine in the database. cscli should be on the same machine as LAPI.

```
cscli machines add [flags]
```

### Examples

```
cscli machines add -m MyTestMachine
cscli machines add --machine TestMachine --password password

```

### Options

```
  -a, --auto              add the machine automatically (generate the machine ID and the password)
  -f, --file string       output file destination
      --force             will force if the machine was already added
  -h, --help              help for add
  -i, --interactive       machine ip address
  -m, --machine string    machine ID to login to the API
  -p, --password string   machine password to login to the API
  -u, --url string        URL of the API
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


