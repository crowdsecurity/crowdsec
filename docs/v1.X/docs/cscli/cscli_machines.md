## cscli machines

Manage local API machines [requires local API]

### Synopsis

To list/add/delete/validate machines.
Note: This command requires database direct access, so is intended to be run on the local API machine.


### Examples

```
cscli machines [action]
```

### Options

```
  -h, --help   help for machines
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
* [cscli machines add](cscli_machines_add.md)	 - add machine to the database.
* [cscli machines delete](cscli_machines_delete.md)	 - delete machines
* [cscli machines list](cscli_machines_list.md)	 - List machines
* [cscli machines validate](cscli_machines_validate.md)	 - validate a machine to access the local API


