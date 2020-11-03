
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


# Behind the scenes

{{v1X.crowdsec.name}} uses the [ent framework](https://entgo.io/) to manage the database.

This is the schema of the database (as seen by `entc describe`)

```
Alert:
	+-----------------+-----------+--------+----------+----------+---------+---------------+-----------+----------------------------------+------------+
	|      Field      |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |            StructTag             | Validators |
	+-----------------+-----------+--------+----------+----------+---------+---------------+-----------+----------------------------------+------------+
	| id              | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"              |          0 |
	| created_at      | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty"      |          0 |
	| updated_at      | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty"      |          0 |
	| scenario        | string    | false  | false    | false    | false   | false         | false     | json:"scenario,omitempty"        |          0 |
	| bucketId        | string    | false  | true     | false    | true    | false         | false     | json:"bucketId,omitempty"        |          0 |
	| message         | string    | false  | true     | false    | true    | false         | false     | json:"message,omitempty"         |          0 |
	| eventsCount     | int32     | false  | true     | false    | true    | false         | false     | json:"eventsCount,omitempty"     |          0 |
	| startedAt       | time.Time | false  | true     | false    | true    | false         | false     | json:"startedAt,omitempty"       |          0 |
	| stoppedAt       | time.Time | false  | true     | false    | true    | false         | false     | json:"stoppedAt,omitempty"       |          0 |
	| sourceIp        | string    | false  | true     | false    | false   | false         | false     | json:"sourceIp,omitempty"        |          0 |
	| sourceRange     | string    | false  | true     | false    | false   | false         | false     | json:"sourceRange,omitempty"     |          0 |
	| sourceAsNumber  | string    | false  | true     | false    | false   | false         | false     | json:"sourceAsNumber,omitempty"  |          0 |
	| sourceAsName    | string    | false  | true     | false    | false   | false         | false     | json:"sourceAsName,omitempty"    |          0 |
	| sourceCountry   | string    | false  | true     | false    | false   | false         | false     | json:"sourceCountry,omitempty"   |          0 |
	| sourceLatitude  | float32   | false  | true     | false    | false   | false         | false     | json:"sourceLatitude,omitempty"  |          0 |
	| sourceLongitude | float32   | false  | true     | false    | false   | false         | false     | json:"sourceLongitude,omitempty" |          0 |
	| sourceScope     | string    | false  | true     | false    | false   | false         | false     | json:"sourceScope,omitempty"     |          0 |
	| sourceValue     | string    | false  | true     | false    | false   | false         | false     | json:"sourceValue,omitempty"     |          0 |
	| capacity        | int32     | false  | true     | false    | false   | false         | false     | json:"capacity,omitempty"        |          0 |
	| leakSpeed       | string    | false  | true     | false    | false   | false         | false     | json:"leakSpeed,omitempty"       |          0 |
	| scenarioVersion | string    | false  | true     | false    | false   | false         | false     | json:"scenarioVersion,omitempty" |          0 |
	| scenarioHash    | string    | false  | true     | false    | false   | false         | false     | json:"scenarioHash,omitempty"    |          0 |
	| simulated       | bool      | false  | false    | false    | true    | false         | false     | json:"simulated,omitempty"       |          0 |
	+-----------------+-----------+--------+----------+----------+---------+---------------+-----------+----------------------------------+------------+
	+-----------+----------+---------+---------+----------+--------+----------+
	|   Edge    |   Type   | Inverse | BackRef | Relation | Unique | Optional |
	+-----------+----------+---------+---------+----------+--------+----------+
	| owner     | Machine  | true    | alerts  | M2O      | true   | true     |
	| decisions | Decision | false   |         | O2M      | false  | true     |
	| events    | Event    | false   |         | O2M      | false  | true     |
	| metas     | Meta     | false   |         | O2M      | false  | true     |
	+-----------+----------+---------+---------+----------+--------+----------+
	
Bouncer:
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	|   Field    |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |          StructTag          | Validators |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	| id         | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"         |          0 |
	| created_at | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty" |          0 |
	| updated_at | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty" |          0 |
	| name       | string    | true   | false    | false    | false   | false         | false     | json:"name,omitempty"       |          0 |
	| api_key    | string    | false  | false    | false    | false   | false         | false     | json:"api_key,omitempty"    |          0 |
	| revoked    | bool      | false  | false    | false    | false   | false         | false     | json:"revoked,omitempty"    |          0 |
	| ip_address | string    | false  | true     | false    | true    | false         | false     | json:"ip_address,omitempty" |          0 |
	| type       | string    | false  | true     | false    | false   | false         | false     | json:"type,omitempty"       |          0 |
	| version    | string    | false  | true     | false    | false   | false         | false     | json:"version,omitempty"    |          0 |
	| until      | time.Time | false  | true     | false    | true    | false         | false     | json:"until,omitempty"      |          0 |
	| last_pull  | time.Time | false  | false    | false    | true    | false         | false     | json:"last_pull,omitempty"  |          0 |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	
Decision:
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	|   Field    |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |          StructTag          | Validators |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	| id         | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"         |          0 |
	| created_at | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty" |          0 |
	| updated_at | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty" |          0 |
	| until      | time.Time | false  | false    | false    | false   | false         | false     | json:"until,omitempty"      |          0 |
	| scenario   | string    | false  | false    | false    | false   | false         | false     | json:"scenario,omitempty"   |          0 |
	| type       | string    | false  | false    | false    | false   | false         | false     | json:"type,omitempty"       |          0 |
	| start_ip   | int64     | false  | true     | false    | false   | false         | false     | json:"start_ip,omitempty"   |          0 |
	| end_ip     | int64     | false  | true     | false    | false   | false         | false     | json:"end_ip,omitempty"     |          0 |
	| scope      | string    | false  | false    | false    | false   | false         | false     | json:"scope,omitempty"      |          0 |
	| value      | string    | false  | false    | false    | false   | false         | false     | json:"value,omitempty"      |          0 |
	| origin     | string    | false  | false    | false    | false   | false         | false     | json:"origin,omitempty"     |          0 |
	| simulated  | bool      | false  | false    | false    | true    | false         | false     | json:"simulated,omitempty"  |          0 |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	+-------+-------+---------+-----------+----------+--------+----------+
	| Edge  | Type  | Inverse |  BackRef  | Relation | Unique | Optional |
	+-------+-------+---------+-----------+----------+--------+----------+
	| owner | Alert | true    | decisions | M2O      | true   | true     |
	+-------+-------+---------+-----------+----------+--------+----------+
	
Event:
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	|   Field    |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |          StructTag          | Validators |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	| id         | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"         |          0 |
	| created_at | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty" |          0 |
	| updated_at | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty" |          0 |
	| time       | time.Time | false  | false    | false    | false   | false         | false     | json:"time,omitempty"       |          0 |
	| serialized | string    | false  | false    | false    | false   | false         | false     | json:"serialized,omitempty" |          0 |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	+-------+-------+---------+---------+----------+--------+----------+
	| Edge  | Type  | Inverse | BackRef | Relation | Unique | Optional |
	+-------+-------+---------+---------+----------+--------+----------+
	| owner | Alert | true    | events  | M2O      | true   | true     |
	+-------+-------+---------+---------+----------+--------+----------+
	
Machine:
	+-------------+-----------+--------+----------+----------+---------+---------------+-----------+------------------------------+------------+
	|    Field    |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |          StructTag           | Validators |
	+-------------+-----------+--------+----------+----------+---------+---------------+-----------+------------------------------+------------+
	| id          | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"          |          0 |
	| created_at  | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty"  |          0 |
	| updated_at  | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty"  |          0 |
	| machineId   | string    | true   | false    | false    | false   | false         | false     | json:"machineId,omitempty"   |          0 |
	| password    | string    | false  | false    | false    | false   | false         | false     | json:"password,omitempty"    |          0 |
	| ipAddress   | string    | false  | false    | false    | false   | false         | false     | json:"ipAddress,omitempty"   |          0 |
	| scenarios   | string    | false  | true     | false    | false   | false         | false     | json:"scenarios,omitempty"   |          0 |
	| version     | string    | false  | true     | false    | false   | false         | false     | json:"version,omitempty"     |          0 |
	| isValidated | bool      | false  | false    | false    | true    | false         | false     | json:"isValidated,omitempty" |          0 |
	| status      | string    | false  | true     | false    | false   | false         | false     | json:"status,omitempty"      |          0 |
	+-------------+-----------+--------+----------+----------+---------+---------------+-----------+------------------------------+------------+
	+--------+-------+---------+---------+----------+--------+----------+
	|  Edge  | Type  | Inverse | BackRef | Relation | Unique | Optional |
	+--------+-------+---------+---------+----------+--------+----------+
	| alerts | Alert | false   |         | O2M      | false  | true     |
	+--------+-------+---------+---------+----------+--------+----------+
	
Meta:
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	|   Field    |   Type    | Unique | Optional | Nillable | Default | UpdateDefault | Immutable |          StructTag          | Validators |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	| id         | <nil>     | false  | false    | false    | false   | false         | false     | json:"id,omitempty"         |          0 |
	| created_at | time.Time | false  | false    | false    | true    | false         | false     | json:"created_at,omitempty" |          0 |
	| updated_at | time.Time | false  | false    | false    | true    | false         | false     | json:"updated_at,omitempty" |          0 |
	| key        | string    | false  | false    | false    | false   | false         | false     | json:"key,omitempty"        |          0 |
	| value      | string    | false  | false    | false    | false   | false         | false     | json:"value,omitempty"      |          0 |
	+------------+-----------+--------+----------+----------+---------+---------------+-----------+-----------------------------+------------+
	+-------+-------+---------+---------+----------+--------+----------+
	| Edge  | Type  | Inverse | BackRef | Relation | Unique | Optional |
	+-------+-------+---------+---------+----------+--------+----------+
	| owner | Alert | true    | metas   | M2O      | true   | true     |
	+-------+-------+---------+---------+----------+--------+----------+

```
