## cscli machines add

add machine to the database.

### Synopsis

Register a new machine in the database. cscli should be on the same machine as LAPI.

```
cscli machines add [flags]
```

### Examples

```

cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword

```

### Options

```
  -a, --auto              automatically generate password (and username if not provided)
  -f, --file string       output file destination (defaults to /etc/crowdsec/local_api_credentials.yaml)
      --force             will force add the machine if it already exist
  -h, --help              help for add
  -i, --interactive       interfactive mode to enter the password
  -p, --password string   machine password to login to the API
  -u, --url string        URL of the local API
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


