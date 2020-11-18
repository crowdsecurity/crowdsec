# Crowdsec configuration

{{v1X.crowdsec.Name}} has a main `yaml` configuration file, usually located in `/etc/crowdsec/config.yaml`.

## Configuration example

<details>
  <summary>Default configuration</summary>

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

</details>


## Configuration format

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

## Configuration directives

### `common`

```yaml
common:
  daemonize: true
  pid_dir: /var/run/
  log_media: file
  log_level: info
  log_dir: /var/log/
  working_dir: 
```

#### `daemonize`
> bool

Daemonize or not the crowdsec daemon.

#### `pid_dir`
> string

Folder to store PID file.

#### `log_media`
> string

Log media. Can be `stdout` or `file`

#### `log_level`
> string

Log level. Can be `error`, `info`, `debug`, `trace`.

#### `log_folder`
> string

Folder to write log file.

!!! warning
    Works only with `log_media = file`.

#### `working_dir`
> string

Current working directory.



### `config_paths`

This section contains most paths to various sub configuration items.


```yaml
config_paths:
  config_dir: /etc/crowdsec/
  data_dir: /var/lib/crowdsec/data
  #simulation_path: /etc/crowdsec/config/simulation.yaml
  #hub_dir: /etc/crowdsec/hub/
  #index_path: ./config/hub/.index.json
```

#### `config_dir`
> string

The main configuration directory of crowdsec.

#### `data_dir`
> string

This is where crowdsec is going to store data, such as files downloaded by scenarios, geolocalisation database, metabase configuration database, or even SQLite database.

#### `simulation_path`
> string

The path to the {{v1X.simulation.htmlname}} configuration

#### `hub_dir`
> string

The directory where `cscli` will store parsers, scenarios, collections and such

#### `index_path`
> string

Tath to the `.index.json` file downloaded by `cscli` to know the list of available configurations


### `crowdsec_service`

This section is only used by crowdsec agent.


```yaml
crowdsec_service:
  #acquisition_path: ./config/acquis.yaml
  parser_routines: 1
```


#### `parser_routines`
> int

Number of dedicated goroutines for parsing files.

#### `buckets_routines` 
> int

Number of dedicated goroutines for managing live buckets.

#### `output_routines`
> int

Number of dedicated goroutines for pushing data to local api.

#### `acquisition_path` :
> string

Path to the yaml file containing logs that needs to be read


## cscli

This section is only used by `cscli`.

```yaml
cscli:
  output: human
  hub_branch: master
```

#### `output`

The default output format (human, json or raw)

#### `hub_branch`

The git branch on which `cscli` is going to fetch configurations


## `db_config`

Please refer to the [database configuration](/Crowdsec/v1/references/database).

## `api`

The api section is used by both `cscli`, `crowdsec` and the local API.

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

### `client`

The client subsection is used by `crowdsec` and `cscli` :

#### `insecure_skip_verify`

Allows the use of https with self-signed certificates

#### `credentials_path`

Path to the credential files (contains API url + login/password)

### `server`

the server subsection is used only the local API.

#### `listen_uri`
> string

Address and port listen configuration

#### `profiles_path`
> string

The path to the {{v1X.profiles.htmlname}} configuration

#### `online_client`


##### `credentials_path`
> string

Path to a file containing credentials for the Central API

#### `tls`

if present, holds paths to certs and key files

##### `cert_file`
> string

Path to certificate file.

##### `key_file`
> string

Path to certficate key file.

## prometheus 

This section is used by local API and crowdsec.

```yaml
prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
```


#### `enabled`

Allows to enable/disable prometheus instrumentation

#### `level`

Can be `full` (all metrics) or `aggregated` (to allow minimal metrics that will keep cardinality low)

#### `listen_addr`

Prometheus listen url

#### `listen_port`

Prometheus listen port
