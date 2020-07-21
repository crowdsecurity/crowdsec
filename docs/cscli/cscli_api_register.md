## cscli api register

Register on Crowdsec API

### Synopsis

This command will register your machine to crowdsec API to allow you to receive list of malveolent IPs. 
		The printed machine_id and password should be added to your api.yaml file.

```
cscli api register [flags]
```

### Examples

```
cscli api register
```

### Options

```
  -h, --help   help for register
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli api](cscli_api.md)	 - Crowdsec API interaction


