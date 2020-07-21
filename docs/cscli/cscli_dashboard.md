## cscli dashboard

Start a dashboard (metabase) container.

### Synopsis

Start a metabase container exposing dashboards and metrics.

### Examples

```
cscli dashboard setup
cscli dashboard start
cscli dashboard stop
cscli dashboard setup --force
```

### Options

```
  -h, --help   help for dashboard
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

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli dashboard setup](cscli_dashboard_setup.md)	 - Setup a metabase container.
* [cscli dashboard start](cscli_dashboard_start.md)	 - Start the metabase container.
* [cscli dashboard stop](cscli_dashboard_stop.md)	 - Stops the metabase container.


