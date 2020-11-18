# Crowdsec configuration file

{{v1X.crowdsec.Name}} has a main `yaml` configuration file, usually located in `/etc/crowdsec/config.yaml`.

Here is an example :

```yaml
common:
  daemonize: true
  pid_dir: /var/run/
  log_media: file
  log_level: info
  log_dir: /var/log/
  working_dir: .
config_paths:
  config_dir: /etc/crowdsec/
  data_dir: /var/lib/crowdsec/data
  #simulation_path: /etc/crowdsec/config/simulation.yaml
  #hub_dir: /etc/crowdsec/hub/
  #index_path: ./config/hub/.index.json
crowdsec_service:
  #acquisition_path: ./config/acquis.yaml
  parser_routines: 1
cscli:
  output: human
  hub_branch: wip_lapi
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
  user: crowdsec
  #log_level: info
  password: crowdsec
  db_name: crowdsec
  host: "127.0.0.1"
  port: 3306
  flush:
    max_items: 5000
    max_age: 7d
api:
  client:
    insecure_skip_verify: true # default true
    credentials_path: /etc/crowdsec/local_api_credentials.yaml
  server:
    #log_level: info
    listen_uri: localhost:8080
    profiles_path: /etc/crowdsec/profiles.yaml
    online_client: # Crowdsec API
      credentials_path: /etc/crowdsec/online_api_credentials.yaml
#    tls:
#      cert_file: /etc/crowdsec/ssl/cert.pem
#      key_file: /etc/crowdsec/ssl/key.pem
prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
```


The various relevant sections of the configuration file are :

## common

```yaml
common:
  daemonize: true
  pid_dir: /var/run/
  log_media: file
  log_level: info
  log_dir: /var/log/
  working_dir: 
```

This section is used by both the Local API and crowdsec itself. Parameters are relevant to daemonization aspects.


## config_paths

```yaml
config_paths:
  config_dir: /etc/crowdsec/
  data_dir: /var/lib/crowdsec/data
  #simulation_path: /etc/crowdsec/config/simulation.yaml
  #hub_dir: /etc/crowdsec/hub/
  #index_path: ./config/hub/.index.json
```

This section contains most paths to various sub configuration items :

 - `config_dir` : the main configuration directory of crowdsec
 - `data_dir` : this is where crowdsec is going to store data, such as files downloaded by scenarios, geolocalisation database, metabase configuration database, or even SQLite database.
 - `simulation_path` : the path to the {{v1X.simulation.htmlname}} configuration
 - `hub_dir` : the directory where `cscli` will store parsers, scenarios, collections and such
 - `index_path` : path to the `.index.json` file downloaded by `cscli` to know the list of available configurations


## crowdsec_service


```yaml
crowdsec_service:
  #acquisition_path: ./config/acquis.yaml
  parser_routines: 1
```

This section is only used by crowdsec agent : 

 - `parser_routines`, `buckets_routines` and `output_routines` allow to control the number of dedicated goroutines for parsing files, managing live bucket and pushing data to local api
 - `acquisition_path` : the path to the yaml file containing logs that needs to be read


## cscli

```yaml
cscli:
  output: human
  hub_branch: master
```

This section is only used by `cscli` :

 - `output` : the default output format (human, json or raw)
 - `hub_branch` : the git branch on which `cscli` is going to fetch configurations

## db_config

```yaml
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
  user: crowdsec
  #log_level: info
  password: crowdsec
  db_name: crowdsec
  host: "127.0.0.1"
  port: 3306
  flush:
    max_items: 5000
    max_age: 7d
```

This section is used by both `cscli` and Local API :

 - `type` : the type of database (sqlite, mysql or postgresql)
 - `log_level` : the dedicated log level for database operations (error, warning, info, debug, trace)
 - `flush` : a flush policy to keep crowdsec's database reasonable. Items that are older than `max_age` are going to be deleted, and/or `max_items` alerts will be kept in database at the same time
 - `db_path` : (sqlite only) path to the database
 - `user` : (mysql/postgresql) username for database
 - `password` : (mysql/postgresql) password for database
 - `db_name` : (mysql/postgresql) name of database
 - `host` : (mysql/postgresql) host of database
 - `port` : (mysql/postgresql) port of database


## api


```yaml
api:
  client:
    insecure_skip_verify: true # default true
    credentials_path: /etc/crowdsec/local_api_credentials.yaml
  server:
    #log_level: info
    listen_uri: localhost:8080
    profiles_path: /etc/crowdsec/profiles.yaml
    online_client: # Crowdsec API
      credentials_path: /etc/crowdsec/online_api_credentials.yaml
#    tls:
#      cert_file: /etc/crowdsec/ssl/cert.pem
#      key_file: /etc/crowdsec/ssl/key.pem
```

The api section is used by both `cscli`, `crowdsec` and the local API.
The client subsection is used by `crowdsec` and `cscli` :

 - `insecure_skip_verify` : allows the use of https with self-signed certificates
 - `credentials_path` : a path to the credential files (contains url of api + login/password)

the server subsection is used only the local API :

 - `listen_uri` : address and port listen configuration
 - `profiles_path` : the path to the {{v1X.profiles.htmlname}} configuration
 - `online_client` : has only one parameter with is `credentials_path`, a path to a file containing credentials for the Central API
 - `tls` : if present, holds paths to certs and key files


## prometheus 

```yaml
prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
```

This section is used by local API and crowdsec :

 - `enabled` : allows to enable/disable prometheus instrumentation
 - `level` : can be `full` (all metrics) or `aggregated` (to allow minimal metrics that will keep cardinality low)
 - `listen_addr` and `listen_port` : configure where prometheus endpoint is listening

