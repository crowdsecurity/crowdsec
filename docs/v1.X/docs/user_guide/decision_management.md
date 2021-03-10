!!! info 

    Please see your local `sudo {{v1X.cli.bin}} help decisions` for up-to-date documentation.

## List active decisions

```bash
sudo {{v1X.cli.bin}} decisions list
```

<details>
  <summary>example</summary>
```bash
$ sudo cscli decisions list
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
| ID  | SOURCE    | SCOPE:VALUE |               REASON               | ACTION | COUNTRY | AS | EVENTS |     EXPIRATION     | ALERT ID |
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
| 802 | cscli     | Ip:1.2.3.5  | manual 'ban' from                  | ban    |         |    |      1 | 3h50m58.10039043s  |     802  |
|     |           |             | 'b76cc7b1bbdc489e93909d2043031de8' |        |         |    |        |                    |          |
| 801 | crowdsec  | Ip:1.2.3.4  | crowdsecurity/ssh-bf               | ban    |         |    |      6 | 3h59m45.100387557s |     801  |
+-----+-----------+-------------+------------------------------------+--------+---------+----+--------+--------------------+----------+
```

</details>
 - `SOURCE` : the source of the decisions:
    - `crowdsec` : decision from crowdsec agent
    - `cscli`    : decision from `cscli` (manual decision)
    - `api`      : decision from crowdsec API
 - `SCOPE:VALUE` is the target of the decisions :
    - "scope" : the scope of the decisions (`ip`, `range`, `user` ...)
    - "value" : the value to apply on the decisions (<ip_addr>, <ip_range>, <username> ...)
 - `REASON` is the scenario that was triggered (or human-supplied reason)
 - `ACTION` is the type of the decision (`ban`, `captcha` ...)
 - `COUNTRY` and `AS` are provided by GeoIP enrichment if present
 - `EVENTS` number of event that triggered this decison
 - `EXPIRATION` is the time left on remediation
 - `ALERT ID` is the ID of the corresponding alert


Check [command usage](/Crowdsec/v1/cscli/cscli_decisions_list/) for additional filtering and output control flags.


## Add a decision
 * default `duration`: `4h`
 * default `type` : `ban`


> Add a decision (ban) on IP  `1.2.3.4` for 24 hours, with reason 'web bruteforce'

```bash
sudo {{v1X.cli.bin}} decisions add --ip 1.2.3.4 --duration 24h --reason "web bruteforce"
```

> Add a decision (ban) on range  `1.2.3.0/24` for 4 hours, with reason 'web bruteforce'

```bash
sudo {{v1X.cli.bin}} decisions add --range 1.2.3.0/24 --reason "web bruteforce"
```


> Add a decision (captcha) on ip `1.2.3.4` for 4hours (default duration), with reason 'web bruteforce'

```bash
sudo {{v1X.cli.bin}} decisions add --ip 1.2.3.4 --reason "web bruteforce" --type captcha
```



## Delete a decision

> delete the decision on IP `1.2.3.4`

```bash
sudo {{v1X.cli.bin}} decisions delete --ip 1.2.3.4
```

> delete the decision on range 1.2.3.0/24

```bash
sudo {{v1X.cli.bin}} decisions delete --range 1.2.3.0/24
```

!!! warning
      Please note that `cscli decisions list` will show you only the latest alert per given ip/scope.
      However, several decisions targeting the same IP can exist. If you want to be sure to clear all decisions for a given ip/scope, use `cscli decisions delete -i x.x.x.x`





## Delete all existing bans

> Flush all the existing bans

```bash
sudo {{v1X.cli.bin}} decisions delete --all
```

!!! warning
     This will as well remove any existing ban



