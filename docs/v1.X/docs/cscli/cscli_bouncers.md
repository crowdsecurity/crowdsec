## cscli bouncers

Manage bouncers [requires local API]

### Synopsis

To list/add/delete bouncers.
Note: This command requires database direct access, so is intended to be run on Local API/master.


### Options

```
  -h, --help   help for bouncers
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
* [cscli bouncers add](cscli_bouncers_add.md)	 - add bouncer
* [cscli bouncers delete](cscli_bouncers_delete.md)	 - delete bouncer
* [cscli bouncers list](cscli_bouncers_list.md)	 - List bouncers


