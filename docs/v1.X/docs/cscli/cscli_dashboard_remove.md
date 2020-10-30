## cscli dashboard remove

removes the metabase container.

### Synopsis

removes the metabase container using docker.

```
cscli dashboard remove [flags]
```

### Examples

```

cscli dashboard remove
cscli dashboard remove --force
 
```

### Options

```
  -f, --force   Force remove : stop the container if running and remove.
  -h, --help    help for remove
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

* [cscli dashboard](cscli_dashboard.md)	 - Manage your metabase dashboard container


