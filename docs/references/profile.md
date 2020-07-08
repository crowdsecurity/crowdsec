# Profile

The output mechanism is composed of plugins. In order to store the bans for {{blockers.htmlname}}, at least one backend plugin must be loaded. Else, bans will not be stored and decisions cannot be applied. 

Please see [here](https://github.com/crowdsecurity/crowdsec/tree/master/plugins/backend) for the available backend plugin.

In order to filter which signals will be sent to which plugin, {{crowdsec.name}} use a system of `profile` that can allow to granularly process your bans and signals.

## Profile

Here is a sample of a profile configuration:

```yaml
profile: <profile_name>
filter: "<filter_expression>"
api: true # default true : send signal to crowdsec API
remediation: # remediation to apply
  ban: true
  duration: 4h
outputs:  # here choose your output plugins for this profile
    - plugin: plugin1
      custom_config: <config>
    - plugin: plugin2

```

The default configuration that is deployed with {{crowdsec.name}} is the following one:
```yaml
profile: default_remediation
filter: "sig.Labels.remediation == 'true'"
api: true # If no api: specified, will use the default config in default.yaml
remediation:
  ban: true
  duration: 4h
outputs:
  - plugin: sqlite
    store: true # we want to store decision in SQLite for ban
---
profile: default_notification
filter: "sig.Labels.remediation != 'true'"
#remediation is empty, it means non taken
api: false
outputs:
  - plugin: sqlite  # If we do not want to push, we can remove this line and the next one
    store: false
```

Here we can use {{filter.htmlname}} like in parsers and scenarios with the {{signal.htmlname}} object to choose which signal will be process by which plugin.

### Learning mode like

Here is an example of a `profile.yaml` file that we can use for a learning mode (by don't storing all the decision in the backend database except the ones we are confident):
```yaml
profile: default_remediation
filter: "sig.Labels.remediation == 'true'"
api: true # If no api: specified, will use the default config in default.yaml
remediation:
  ban: true
  duration: 4h
outputs:
  - plugin: sqlite
    store: false # We don't store decisions in SQLite because we want a learning mode
---
profile: only ban ssh bruteforce scenario
filter: "sig.Labels.Scenario == 'crowdsecurity/ssh-bf'"
api: true
remediation:
  ban: true
  duration: 4h
outputs:
  - plugin: sqlite  # If we do not want to push, we can remove this line and the next one
    store: true
```

### Plugins

Plugins are part of the output mecanism that store decisions in a database backend to be used by a blocker for bans.

Plugins configuration file are stored in `{{plugins.configpath}}`. {{crowdsec.name}} will scan this folder to load all the plugins. Each configuration file should provide the path to the plugin binary. By default they are stored in `{{plugins.binpath}}`.

!!! info
        If you want crowdsec to not load a plugin, `mv` or `rm` its configuration file in `{{plugins.configpath}}`

Here is a sample of a plugin configuration file stored in `{{plugins.configpath}}`:
```yaml
name: <plugin_name>
path: <path_to_plugin_binary> # 
config: <plugin_config> # in a form of key(string)/value(string)
```

For the plugin sqlite, here is its configuration file:
```yaml
name: sqlite
path: /usr/local/lib/crowdsec/plugins/backend/sqlite.so
config:
  db_path: /var/lib/crowdsec/data/crowdsec.db
  flush: true
```

