# Databases

By default, the crowdsec Local API use `SQLite` as backend storage. But in case you except a lot of traffic on your local API, you should use `MySQL` or `PostgreSQL`.

For `SQLite`, there is nothing to do on your side in order to make it work with crowdsec. But for `MySQL` and `PostgreSQL` , you have to create the database and the user.

## MySQL

Connect to your `MySQL` server and run the following command:

```
CREATE DATABASE crowdsec;
CREATE USER 'crowdsec'@'%' IDENTIFIED BY '<password>';
GRANT ALL PRIVILEGES ON crowdsec.* TO 'crowdsec'@'%';
FLUSH PRIVILEGES;
```

Then edit `{{v1X.config.crowdsec_config_file}}` to update the [`db_config`](/Crowdsec/v1/references/database/#db_config) part.

You can now start/restart crowdsec.

## PostgreSQL

Connect to your `PostgreSQL` server and run the following command:

```
CREATE DATABASE crowdsec;
CREATE USER crowdsec WITH PASSWORD '<password>';
GRANT ALL PRIVILEGES ON DATABASE crowdsec TO crowdsec;
```

Then edit `{{v1X.config.crowdsec_config_file}}` to update the [`db_config`](/Crowdsec/v1/references/database/#db_config) part.

You can now start/restart crowdsec.