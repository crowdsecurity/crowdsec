<!-- TBD: Decrire la partie du config.yaml qui indique ou LAPI ecrit
 - parler du schema de donnees?
  -->
# Database

The database is mostly used by the [local API]({{v1X.lapi.htmlname}}) but also by {{v1X.cli.user_guide}} for some tasks.

Currently, 3 databases are supported:

-  `sqlite` (default database)

-  `mysql`

-  `postegresql`


!!! warning
    It is recommanded to use `mysql` or `postegresql` if you expect to have a lot of traffic on the API.


The database configuration can be found in the `crowdsec` configuration file (default: {{v1X.config.crowdsec_config_file}}).

Its located under the `db_config` block.

## Configuration Examples

<details>
  <summary>SQLite</summary>

```yaml
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
```
</details>
<details>
<summary>MySQL</summary>

```yaml
db_config:
  type: mysql
  user: crowdsec
  password: crowdsecpassword
  db_name: crowdsec
  host: "127.0.0.1"
  port: 3306
```
</details>
<details>
<summary>PostegreSQL</summary>

```yaml
db_config:
  type: postegresql
  user: crowdsec
  password: crowdsecpassword
  db_name: crowdsec
  host: "127.0.0.1"
  port: 3306
```

</details>

## Configuration Format


```
db_config:
  type:     <db_type>
  
  db_path:  <path_to_database_file>  # in case of sqlite
  
  user:     <db_user>      # in case of mysql/pgsql
  password: <db_password>  # in case of mysql/pgsql
  db_name:  <db_name>      # in case of mysql/pgsql
  host:     <db_host_ip>   # in case of mysql/pgsql
  port:     <db_host_port> # in case of mysql/pgsql
```



## Configuration Directives

### `type`

```yaml
db_config:
  type: sqlite
```

The `type` of database to use. It can be:

- `sqlite`
- `mysql`
- `postegresql`

### `db_path`

```yaml
db_config:
  type: sqlite
  db_path: "/var/lib/crowdsec/data/crowdsec.db
```

The path to the database file (only if the type of database is `sqlite`)

### `user`

```yaml
db_config:
  type: mysql|postegresql

  user: foo
```
The username to connect to the database (only if the type of database is `mysql` or `postegresql`)

### `password`

```yaml
db_config:
  type: mysql|postegresql

  password: foobar
```
The password to connect to the database (only if the type of database is `mysql` or `postegresql`)

### `db_name`

```yaml
db_config:
  type: mysql|postegresql

  db_name: crowdsec
```
The database name to connect to (only if the type of database is `mysql` or `postegresql`)

### `db_host`

```yaml
db_config:
  type: mysql|postegresql

  user: foo
```
The host to connect to (only if the type of database is `mysql` or `postegresql`)

### `db_port`

```yaml
db_config:
  type: mysql|postegresql

  user: foo
```
The port to connect to (only if the type of database is `mysql` or `postegresql`)

