!!! info 

    Please see your local `{{cli.bin}} help ban` for up-to-date documentation.

## List bans

```bash
{{cli.bin}} ban list
```

<details>
  <summary>example</summary>
```bash
bui@sd:~$ cli ban list
4 local decisions:
+--------+----------------+----------------------+------+--------+---------+--------------------------------+--------+------------+
| SOURCE |       IP       |        REASON        | BANS | ACTION | COUNTRY |               AS               | EVENTS | EXPIRATION |
+--------+----------------+----------------------+------+--------+---------+--------------------------------+--------+------------+
| cli    | 1.1.1.1        | spammer              |    1 | ban    |         |                                |      0 | 23h59m58s  |
| local  | 2.2.2.2        | crowdsecurity/ssh-bf |    1 | ban    | FR      | 3215 Orange                    |      6 | 3h7m30s    |
| local  | 3.3.3.3        | crowdsecurity/ssh-bf |    1 | ban    | US      | 3266 Joao Carlos de Almeida    |      6 | 57m17s     |
|        |                |                      |      |        |         | Silveira trading as Bitcanal   |        |            |
| local  | 4.4.4.4        | crowdsecurity/ssh-bf |    1 | ban    | FR      | 15557 SFR SA                   |      6 | 5m11s      |
+--------+----------------+----------------------+------+--------+---------+--------------------------------+--------+------------+
And 64 records from API, 32 distinct AS, 19 distinct countries

```
</details>

 - `SOURCE` is the source of the decision :
    - "local" : the decision has been taken by {{crowdsec.name}}
    - "cli" : the decision has been made with {{cli.name}} (ie. `{{cli.name}} ban ip 1.2.3.4 24h "because"`)
    - "api" : the decision has been pushed to you by the API (because there is a consensus about this ip)
 - `IP` is the IP or the IP range impacted by the decision
 - `REASON` is the scenario that was triggered (or human-supplied reason)
 - `BANS` is the number of "active" remediation against this IP
 - `COUNTRY` and `AS` are provided by GeoIP enrichment if present
 - `EXPIRATION` is the time left on remediation


Check [command usage](/cscli/cscli_ban_list/) for additional filtering and output control flags.


## Delete a ban

> delete the ban on IP `1.2.3.4`

```bash
{{cli.bin}} ban del ip 1.2.3.4
```

> delete the ban on range 1.2.3.0/24

```bash
{{cli.bin}} ban del range 1.2.3.0/24
```


## Add a ban manually

> Add a ban on IP  `1.2.3.4` for 24 hours, with reason 'web bruteforce'

```bash
{{cli.bin}} ban add ip 1.2.3.4 24h "web bruteforce"
```

> Add a ban on range  `1.2.3.0/24` for 24 hours, with reason 'web bruteforce'

```bash
{{cli.bin}} ban add range 1.2.3.0/24 "web bruteforce"
```



## Flush all existing bans

> Flush all the existing bans

```bash
{{cli.bin}} ban flush
```

!!! warning
     This will as well remove any existing ban



