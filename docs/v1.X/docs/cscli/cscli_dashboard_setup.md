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
cscli dashboard setup --listen 0.0.0.0
cscli dashboard setup -l 0.0.0.0 -p 443 --password <password>
 
```

### Options

```
  -d, --dir string        Shared directory with metabase container.
  -f, --force             Force setup : override existing files.
  -h, --help              help for setup
  -l, --listen string     Listen address of container (default "127.0.0.1")
      --password string   metabase password
  -p, --port string       Listen port of container (default "3000")
  -y, --yes               force  yes
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

* [cscli dashboard](cscli_dashboard.md)	 - Manage your metabase dashboard container [requires local API]


