## cscli bouncers add

add bouncer

### Synopsis

add bouncer

```
cscli bouncers add MyBouncerName [--length 16] [flags]
```

### Examples

```
cscli bouncers add MyBouncerName
cscli bouncers add MyBouncerName -l 24
```

### Options

```
  -h, --help         help for add
  -l, --length int   length of the api key (default 16)
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

* [cscli bouncers](cscli_bouncers.md)	 - Manage bouncers [requires local API]


