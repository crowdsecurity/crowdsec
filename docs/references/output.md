# Output

The output mechanism is composed of plugins. In order to store the bans for {{blockers.htmlname}}, at least one backend plugin must be loaded. Else, bans will not be stored and decisions cannot be applied. 


Currently the supported backends are SQLite (default) and MySQL.

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
  - plugin: database
---
profile: default_notification
filter: "sig.Labels.remediation != 'true'"
#remediation is empty, it means non taken
api: false
outputs:
  - plugin: database  # If we do not want to push, we can remove this line and the next one
    store: false
```

Here we can use {{filter.htmlname}} like in parsers and scenarios with the {{signal.htmlname}} object to choose which signal will be process by which plugin.



# Backend database configuration

The `/etc/crowdsec/plugins/backend/database.yaml` file allows you to configure to which backend database you'd like to write. {{crowdsec.Name}} support SQLite and MySQL via [gorm](https://gorm.io/docs/).

```yaml
name: database
path: /usr/local/lib/crowdsec/plugins/backend/database.so
config:
  ## DB type supported (mysql, sqlite)
  ## By default it using sqlite
  type: sqlite

  ## mysql options
  # db_host: localhost
  # db_username: crowdsec
  # db_password: password
  # db_name: crowdsec

  ## sqlite options
  db_path: /var/lib/crowdsec/data/crowdsec.db

  ## Other options
  flush: true
  # debug: true

```

## SQLite 

SQLite is the default backend database, so you don't have to touch anything.

## MySQL

If you want to use MySQL as a backend database (which is suitable to distributed architectures), you need to have root privileges (ie. `mysql -u root -p`) on you MySQL database to type the following commands :

```bash
#create the database for crowdsec
CREATE database crowdsec
#create the dedicated user
CREATE USER 'crowdsec'@'localhost' IDENTIFIED BY 'verybadpassword';
#grant the privileges
GRANT ALL PRIVILEGES ON crowdsec.* TO 'crowdsec'@'localhost';
#allow backward compatibility for mysql >= 5.7
SET GLOBAL sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''));
```

Then, configure accordingly your `/etc/crowdsec/plugins/backend/database.yaml` :

```yaml
name: database
path: /usr/local/lib/crowdsec/plugins/backend/database.so
config:
  ## DB type supported (mysql, sqlite)
  ## By default it using sqlite
  type: mysql

  ## mysql options
  db_host: localhost
  db_username: crowdsec
  db_password: verybadpassword
  db_name: crowdsec

  ## sqlite options
  #db_path: /var/lib/crowdsec/data/crowdsec.db

  ## Other options
  flush: true
  # debug: true
```


# Plugins

Plugins configuration file are stored in `{{plugins.configpath}}`. {{crowdsec.Name}} will scan this folder to load all the plugins. Each configuration file should provide the path to the plugin binary. By default they are stored in `{{plugins.binpath}}`.

!!! info
        If you want crowdsec to not load a plugin, `mv` or `rm` its configuration file in `{{plugins.configpath}}`

Here is a sample of a plugin configuration file stored in `{{plugins.configpath}}`:
```yaml
name: <plugin_name>
path: <path_to_plugin_binary> # 
config: <plugin_config> # in a form of key(string)/value(string)
```

For the plugin database, here is its configuration file:
```yaml
name: database
path: /usr/local/lib/crowdsec/plugins/backend/database.so
config:
  db_path: /var/lib/crowdsec/data/crowdsec.db
  flush: true
```

