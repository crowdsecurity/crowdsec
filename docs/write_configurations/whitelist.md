# What are whitelists

Whitelists are special parsers that allow you to "discard" events, and can exist at two different steps :

 - *Parser whitelists* : Allows you to discard an event at parse time, so that it never hits the buckets.
 - *PostOverflow whitelists* : Those are whitelists that are checked *after* the overflow happens. It is usually best for whitelisting process that can be expensive (such as performing reverse DNS on an IP, or performing a `whois` of an IP).

!!! info
    While the whitelists are the same for parser or postoverflows, beware that field names might change.
    Source ip is usually in `evt.Meta.source_ip` when it's a log, but `evt.Overflow.Source_ip` when it's an overflow


The whitelist can be based on several criteria :

 - specific ip address : if the event/overflow IP is the same, event is whitelisted
 - ip ranges : if the event/overflow IP belongs to this range, event is whitelisted
 - a list of {{expr.htmlname}} expressions : if any expression returns true, event is whitelisted

Here is an example showcasing configuration :

```yaml
name: crowdsecurity/my-whitelists
description: "Whitelist events from my ipv4 addresses"
#it's a normal parser, so we can restrict its scope with filter
filter: "1 == 1"
whitelist:
  reason: "my ipv4 ranges"
  ip: 
    - "127.0.0.1"
  cidr:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  expression:
  #beware, this one will work *only* if you enabled the reverse dns (crowdsecurity/rdns) enrichment postoverflow parser
    - evt.Enriched.reverse_dns endsWith ".mycoolorg.com."
  #this one will work *only* if you enabled the geoip (crowdsecurity/geoip-enrich) enrichment parser
    - evt.Enriched.IsoCode == 'FR'
```


# Whitelists in parsing

When a whitelist is present in parsing `/etc/crowdsec/config/parsers/...`, it will be checked/discarded before being poured to any bucket. These whitelists intentionally generate no logs and are useful to discard noisy false positive sources.

## Whitelist by ip

Let's assume we have a setup with a `crowdsecurity/nginx` collection enabled and no whitelists.

Thus, if I "attack" myself :

```bash
nikto -host myfqdn.com
```

my own IP will be flagged as being an attacker :

```bash
$ tail -f /var/log/crowdsec.log 
ime="07-07-2020 16:13:16" level=warning msg="80.x.x.x triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-bad-user-agent]" bucket_id=cool-smoke event_time="2020-07-07 16:13:16.579581642 +0200 CEST m=+358819.413561109" scenario=crowdsecurity/http-bad-user-agent source_ip=80.x.x.x
time="07-07-2020 16:13:16" level=warning msg="80.x.x.x triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-probing]" bucket_id=green-silence event_time="2020-07-07 16:13:16.737579458 +0200 CEST m=+358819.571558901" scenario=crowdsecurity/http-probing source_ip=80.x.x.x
time="07-07-2020 16:13:17" level=warning msg="80.x.x.x triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-crawl-non_statics]" bucket_id=purple-snowflake event_time="2020-07-07 16:13:17.353641625 +0200 CEST m=+358820.187621068" scenario=crowdsecurity/http-crawl-non_statics source_ip=80.x.x.x
time="07-07-2020 16:13:18" level=warning msg="80.x.x.x triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-sensitive-files]" bucket_id=small-hill event_time="2020-07-07 16:13:18.005919055 +0200 CEST m=+358820.839898498" scenario=crowdsecurity/http-sensitive-files source_ip=80.x.x.x
^C
$ {{cli.bin}} ban list
4 local decisions:
+--------+---------------+-----------------------------------+------+--------+---------+---------------------------+--------+------------+
| SOURCE |      IP       |              REASON               | BANS | ACTION | COUNTRY |            AS             | EVENTS | EXPIRATION |
+--------+---------------+-----------------------------------+------+--------+---------+---------------------------+--------+------------+
| local  | 80.x.x.x   | crowdsecurity/http-bad-user-agent |    4 | ban    | FR      | 21502 SFR SA              |     60 | 3h59m3s    |
...

```


### Create the whitelist by IP

Let's create a `/etc/crowdsec/crowdsec/parsers/s02-enrich/mywhitelists.yaml` file with the following content :

```yaml
name: crowdsecurity/whitelists
description: "Whitelist events from my ip addresses"
whitelist:
  reason: "my ip ranges"
    ip:
        - "80.x.x.x"
```

and reload {{crowdsec.name}} : `sudo systemctl reload crowdsec`

### Test the whitelist

Thus, if we restart our attack :

```bash
nikto -host myfqdn.com
```

And we don't get bans :

```bash
$ tail -f /var/log/crowdsec.log  
...
^C
$ {{cli.bin}} ban list
No local decisions.
And 21 records from API, 15 distinct AS, 12 distinct countries

```

Here, we don't get *any* logs, as the event have been discarded at parsing time.


## Create whitelist by expression

Now, let's make something more tricky : let's whitelist a **specific** user-agent (of course, it's just an example, don't do this at home !). The [hub's taxonomy](https://hub.crowdsec.net/fields) will helps us to find which data is present in which field.

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
nikto -host myfqdn.com
```

```bash
$ tail -f /var/log/crowdsec.log  
...
time="07-05-2020 09:39:09" level=info msg="Event is whitelisted by Expr !" filter= name=solitary-leaf stage=s02-enrich
...
```


# Whitelist in PostOverflows 

Whitelists in PostOverflows are applied *after* the bucket overflow happens.
It has the advantage of being triggered only once we are about to take decision about an IP or Range, and thus happens a lot less often.

A good example is the [crowdsecurity/whitelist-good-actors](https://hub.crowdsec.net/author/crowdsecurity/collections/whitelist-good-actors) collection.

But let's craft ours based on our previous example !
First of all, install the [crowdsecurity/rdns postoverflow](https://hub.crowdsec.net/author/crowdsecurity/configurations/rdns) : it will be in charge of enriching overflows with reverse dns information of the offending IP.

Let's put the following file in `/etc/crowdsec/config/postoverflows/s01-whitelists/mywhitelists.yaml` :

```yaml
name: me/my_cool_whitelist
description: lets whitelist our own reverse dns
whitelist:
  reason: dont ban my ISP
  expression:
  #this is the reverse of my ip, you can get it by performing a "host" command on your public IP for example
    - evt.Enriched.reverse_dns endsWith '.asnieres.rev.numericable.fr.'
```

After reloading {{crowdsec.name}}, and launching (again!) nikto :

```bash
nikto -host myfqdn.com
```


```bash
$ tail -f /var/log/crowdsec.log
ime="07-07-2020 17:11:09" level=info msg="Ban for 80.x.x.x whitelisted, reason [dont ban my ISP]" id=cold-sunset name=me/my_cool_whitelist stage=s01
time="07-07-2020 17:11:09" level=info msg="node warning : no remediation" bucket_id=blue-cloud event_time="2020-07-07 17:11:09.175068053 +0200 CEST m=+2308.040825320" scenario=crowdsecurity/http-probing source_ip=80.x.x.x
time="07-07-2020 17:11:09" level=info msg="Processing Overflow with no decisions 80.x.x.x performed 'crowdsecurity/http-probing' (11 events over 313.983994ms) at 2020-07-07 17:11:09.175068053 +0200 CEST m=+2308.040825320" bucket_id=blue-cloud event_time="2020-07-07 17:11:09.175068053 +0200 CEST m=+2308.040825320" scenario=crowdsecurity/http-probing source_ip=80.x.x.x
...

```

This time, we can see that logs are being produced when the event is discarded.

