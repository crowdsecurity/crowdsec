## Where are whitelists

Whitelists are, as for most configuration, YAML files, and allow you to "discard" signals based on :

 - ip adress or the fact that it belongs to a specific range
 - a {{expr.name}} expression

Here is an example :

```yaml
name: crowdsecurity/my-whitelists
description: "Whitelist events from my ipv4 addresses"
whitelist:
  reason: "my ipv4 ranges"
  ip: 
    - "127.0.0.1"
  cidr:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  expression:
    - "'mycorp.com' in evt.Meta.source_ip_rdns"
```

## Hands on

Let's assume we have a setup with a `crowdsecurity/base-http-scenarios` scenario enabled and no whitelists.

Thus, if I "attack" myself :

```bash
nikto -host 127.0.0.1
```

my own IP will be flagged as being an attacker :

```bash
$ tail -f /var/log/crowdsec.log 
time="07-05-2020 09:23:03" level=warning msg="127.0.0.1 triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-scan-uniques_404]" bucket_id=old-surf event_time="2020-05-07 09:23:03.322277347 +0200 CEST m=+57172.732939890" scenario=crowdsecurity/http-scan-uniques_404 source_ip=127.0.0.1
time="07-05-2020 09:23:03" level=warning msg="127.0.0.1 triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-crawl-non_statics]" bucket_id=lingering-sun event_time="2020-05-07 09:23:03.345341864 +0200 CEST m=+57172.756004380" scenario=crowdsecurity/http-crawl-non_statics source_ip=127.0.0.1
^C
$ {{cli.bin}} ban list
1 local decisions:
+--------+-----------+-------------------------------------+------+--------+---------+----+--------+------------+
| SOURCE |    IP     |               REASON                | BANS | ACTION | COUNTRY | AS | EVENTS | EXPIRATION |
+--------+-----------+-------------------------------------+------+--------+---------+----+--------+------------+
| local  | 127.0.0.1 | crowdsecurity/http-scan-uniques_404 |    2 | ban    |         | 0  |     47 | 3h55m57s   |
+--------+-----------+-------------------------------------+------+--------+---------+----+--------+------------+

```

## Create the whitelist by IP

Let's create a `/etc/crowdsec/crowdsec/parsers/s02-enrich/whitelists.yaml` file with the following content :

```yaml
name: crowdsecurity/whitelists
description: "Whitelist events from private ipv4 addresses"
whitelist:
  reason: "private ipv4 ranges"
  ip: 
    - "127.0.0.1"

```

and restart {{crowdsec.name}} : `sudo systemctl restart {{crowdsec.name}}`

## Test the whitelist

Thus, if we restart our attack :

```bash
nikto -host 127.0.0.1
```

And we don't get bans, instead :

```bash
$ tail -f /var/log/crowdsec.log  
...
time="07-05-2020 09:30:13" level=info msg="Event from [127.0.0.1] is whitelisted by Ips !" filter= name=lively-firefly stage=s02-enrich
...
^C
$ {{cli.bin}} ban list
No local decisions.
And 21 records from API, 15 distinct AS, 12 distinct countries

```



## Create whitelist by expression

Now, let's make something more tricky : let's whitelist a **specific** user-agent (of course, it's just an example, don't do this at home !).

Let's change our whitelist to :

```yaml
name: crowdsecurity/whitelists
description: "Whitelist events from private ipv4 addresses"
whitelist:
  reason: "private ipv4 ranges"
  expression:
   - evt.Parsed.http_user_agent == 'MySecretUserAgent'
```

again, let's restart {{crowdsec.name}} !

For the record, I edited nikto's configuration to use 'MySecretUserAgent' as user-agent, and thus :

```bash
nikto -host 127.0.0.1
```

```bash
$ tail -f /var/log/crowdsec.log  
...
time="07-05-2020 09:39:09" level=info msg="Event is whitelisted by Expr !" filter= name=solitary-leaf stage=s02-enrich
...
```


