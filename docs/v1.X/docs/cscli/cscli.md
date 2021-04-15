## cscli

cscli allows you to manage crowdsec

### Synopsis

cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.

### Options

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config.yaml")
  -o, --output string   Output format : human, json, raw.
      --debug           Set logging to debug.
      --info            Set logging to info.
      --warning         Set logging to warning.
      --error           Set logging to error.
      --trace           Set logging to trace.
  -h, --help            help for cscli
```

### SEE ALSO

* [cscli alerts](cscli_alerts.md)	 - Manage alerts
* [cscli bouncers](cscli_bouncers.md)	 - Manage bouncers [requires local API]
* [cscli capi](cscli_capi.md)	 - Manage interaction with Central API (CAPI)
* [cscli collections](cscli_collections.md)	 - Manage collections from hub
* [cscli completion](cscli_completion.md)	 - Generate completion script
* [cscli config](cscli_config.md)	 - Allows to view current config
* [cscli dashboard](cscli_dashboard.md)	 - Manage your metabase dashboard container [requires local API]
* [cscli decisions](cscli_decisions.md)	 - Manage decisions
* [cscli hub](cscli_hub.md)	 - Manage Hub
* [cscli lapi](cscli_lapi.md)	 - Manage interaction with Local API (LAPI)
* [cscli machines](cscli_machines.md)	 - Manage local API machines [requires local API]
* [cscli metrics](cscli_metrics.md)	 - Display crowdsec prometheus metrics.
* [cscli parsers](cscli_parsers.md)	 - Install/Remove/Upgrade/Inspect parser(s) from hub
* [cscli postoverflows](cscli_postoverflows.md)	 - Install/Remove/Upgrade/Inspect postoverflow(s) from hub
* [cscli scenarios](cscli_scenarios.md)	 - Install/Remove/Upgrade/Inspect scenario(s) from hub
* [cscli simulation](cscli_simulation.md)	 - Manage simulation status of scenarios
* [cscli version](cscli_version.md)	 - Display version and exit.


