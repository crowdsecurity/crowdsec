## cscli dashboard setup

Setup a metabase container.

### Synopsis

Perform a metabase docker setup, download standard dashboards, create a fresh user and start the container

```
cscli dashboard setup [flags]
```

### Examples

```
cscli dashboard setup
cscli dashboard setup --force
cscli dashboard setup -l 0.0.0.0 -p 443
 
```

### Options

```
  -d, --dir string      Shared directory with metabase container. (default "/var/lib/crowdsec/data")
  -f, --force           Force setup : override existing files.
  -h, --help            help for setup
  -l, --listen string   Listen address of container (default "127.0.0.1")
  -p, --port string     Listen port of container (default "3000")
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

* [cscli dashboard](cscli_dashboard.md)	 - Start a dashboard (metabase) container.


