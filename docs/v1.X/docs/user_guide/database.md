# Databases

By default, the crowdsec Local API use `SQLite` as backend storage. But in case you expect a lot of traffic on your local API, you should use `MySQL` or `PostgreSQL`.

For `SQLite`, there is nothing to do to make it work with crowdsec. But for `MySQL` and `PostgreSQL` , you have to create the database and the user.

Please refer to [ent.](https://entgo.io/) [supported database](https://entgo.io/docs/dialects/). At the time of writting :

 - MySQL `5.6.35`, `5.7.26` and `8`
 - MariaDB `10.2` and latest
 - PostgreSQL `10`, `11` and `12`
 - SQLite
 - Gremlin


!!! warning
    When switching an existing instance of crowdsec to a new database backend, you need to register your machine(s) (ie. `cscli machines add -a`) and bouncer(s) to the new database, as data is not migrated.


## MySQL

Connect to your `MySQL` server and run the following commands:

```
mysql> CREATE DATABASE crowdsec;
mysql> CREATE USER 'crowdsec'@'%' IDENTIFIED BY '<password>';
mysql> GRANT ALL PRIVILEGES ON crowdsec.* TO 'crowdsec'@'%';
mysql> FLUSH PRIVILEGES;
```

Then edit `{{v1X.config.crowdsec_config_file}}` to update the [`db_config`](/Crowdsec/v1/references/database/#db_config) part.

You can now start/restart crowdsec.

## PostgreSQL

Connect to your `PostgreSQL` server and run the following commands:

```
postgres=# CREATE DATABASE crowdsec;
postgres=# CREATE USER crowdsec WITH PASSWORD '<password>';
postgres=# GRANT ALL PRIVILEGES ON DATABASE crowdsec TO crowdsec;
```

Then edit `{{v1X.config.crowdsec_config_file}}` to update the [`db_config`](/Crowdsec/v1/references/database/#db_config) part.

You can now start/restart crowdsec.