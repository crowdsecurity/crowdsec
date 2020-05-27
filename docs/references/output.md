# Output

The output mechanism is composed of plugins. In order to store the bans for {{blockers.htmlname}}, at least one backend plugin must be loaded. Else, bans will not be stored and decisions cannot be applied. 

Please see [here](https://github.com/crowdsecurity/crowdsec/tree/master/plugins/backend) for the available backend plugin.

In order to filter which signals will be sent to which plugin, {{crowdsec.name}} use a system of `profile` that can allow to granularly process your bans and signals.

## Profile

Here is a sample of a profile configuration:

```yaml
profile: <profile_name>
filter: "<filter_expression>"
api: true # default true : send signal to crowdsec API
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
  slow: true
  captcha: true
  duration: 4h
outputs:
  - plugin: sqlite
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

## Plugins

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
path: /usr/local/crowdsec/plugins/backend/sqlite.so
config:
  db_path: /var/lib/crowdsec/data/crowdsec.db
  flush: true
```

