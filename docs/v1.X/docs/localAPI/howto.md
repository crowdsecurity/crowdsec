

!!! info

    This page explains how to interact with the local API exposed by crowdsec.

    It's meant to be useful for system administrators, or users that want to create their own bouncers.



## Introduction

This documentation only covers the API usage from the bouncer POV :

 - Authentication via API token (rather than JWT as crowdsec/cscli)
 - Reading decisions

This guide will assume that you already have crowdsec running locally.

## Authentication

Existing tokens can be viewed with `cscli bouncers list` :

```
# cscli bouncers list
-------------------------------------------------------------------------------------------
 NAME                          IP ADDRESS  VALID  LAST API PULL              TYPE  VERSION 
-------------------------------------------------------------------------------------------
 cs-firewall-bouncer-hPrueCas              ✔️      2021-02-25T19:54:46+01:00                
-------------------------------------------------------------------------------------------
```

Let's create a new token with `cscli bouncers add MyTestClient` :

```
# cscli bouncers add MyTestClient
Api key for 'MyTestClient':

   837be58e22a28738066de1be8f53636b

Please keep this key since you will not be able to retrive it!

```

This is the token that we will use to authenticate with the API :

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b" -I localhost:8080/v1/decisions  
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Fri, 26 Feb 2021 12:35:37 GMT
```

Note: if the token is missing or incorrect, you will get a **403** answer.

## API Usage

As stated in the [swagger documentation](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI), bouncer's method are restricted to the `/decisions` path. They allow to query the local decisions in two modes :

 - stream mode : Intended for bouncers that will - on a regular basis - query the local api for new and expired/decisions
 - query mode : Intended for bouncers that want to query the local api about a specific ip/range/username etc.


## Query Mode

To have some data to query for, let's add two decisions to our local API

```bash
▶ sudo cscli decisions add -i 1.2.3.4
INFO[0000] Decision successfully added      
▶ sudo cscli decisions add -r 2.2.3.0/24
INFO[0000] Decision successfully added                  
▶ sudo cscli decisions list
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+
|  ID  | SOURCE |   SCOPE:VALUE    |                       REASON                       | ACTION | COUNTRY | AS | EVENTS |     EXPIRATION     | ALERT ID |
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+
| 2337 | cscli  | Range:2.2.3.0/24 | manual 'ban' from                                  | ban    |         |    |      1 | 3h59m18.079301785s |     1164 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |        |         |    |        |                    |          |
| 2336 | cscli  | Ip:1.2.3.4       | manual 'ban' from                                  | ban    |         |    |      1 | 3h59m11.079297437s |     1163 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |        |         |    |        |                    |          |
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+

```

#### Query mode : IP

We can now try to query the API :

> Query a single banned IP

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?ip=1.2.3.4
[{"duration":"3h51m57.363171728s","id":2336,"origin":"cscli","scenario":"manual 'ban' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"Ip","type":"ban","value":"1.2.3.4"}]
```

> Query a single IP

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?ip=1.2.3.5
null
```

> Query an IP contained in an existing ban

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?ip\=2.2.3.42                    
[{"duration":"3h38m32.349736035s","id":2337,"origin":"cscli","scenario":"manual 'ban' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"Range","type":"ban","value":"2.2.3.0/24"}]
```
_note: notice that the decision returned is the range that we banned earlier and that contains query ip_

#### Query mode : Range

> Query a range in which one of the ban is contained

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?range=1.2.3.0/24\&contains\=false
[{"duration":"3h48m7.676653651s","id":2336,"origin":"cscli","scenario":"manual 'ban' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"Ip","type":"ban","value":"1.2.3.4"}]
```
_note: notice the `contains` flag that is set to false_

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?range=1.2.3.0/24\&contains\=true
null
```

> Query a range which is contained by an existing ban

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?range\=2.2.3.1/25
[{"duration":"3h30m24.773063133s","id":2337,"origin":"cscli","scenario":"manual 'ban' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"Range","type":"ban","value":"2.2.3.0/24"}]
```

### Query mode : non IP centric decisions

While most people will use crowdsec to ban IPs or ranges, decisions can target other scopes and other decisions :

```bash
▶ sudo cscli decisions add --scope username --value myuser --type enforce_mfa
INFO[0000] Decision successfully added                  
▶ sudo cscli decisions list                                                  
+------+--------+------------------+----------------------------------------------------+-------------+---------+----+--------+--------------------+----------+
|  ID  | SOURCE |   SCOPE:VALUE    |                       REASON                       |   ACTION    | COUNTRY | AS | EVENTS |     EXPIRATION     | ALERT ID |
+------+--------+------------------+----------------------------------------------------+-------------+---------+----+--------+--------------------+----------+
| 2338 | cscli  | username:myuser  | manual 'enforce_mfa' from                          | enforce_mfa |         |    |      1 | 3h59m55.384975175s |     1165 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |             |         |    |        |                    |          |
| 2337 | cscli  | Range:2.2.3.0/24 | manual 'ban' from                                  | ban         |         |    |      1 | 3h27m1.384972861s  |     1164 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |             |         |    |        |                    |          |
| 2336 | cscli  | Ip:1.2.3.4       | manual 'ban' from                                  | ban         |         |    |      1 | 3h26m54.384971268s |     1163 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |             |         |    |        |                    |          |
+------+--------+------------------+----------------------------------------------------+-------------+---------+----+--------+--------------------+----------+
```



> Query a decision on a given user

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?scope\=username\&value\=myuser
[{"duration":"3h57m59.021170481s","id":2338,"origin":"cscli","scenario":"manual 'enforce_mfa' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"username","type":"enforce_mfa","value":"myuser"}]
```

> Query a decision on a given user

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?scope\=username\&value\=myuser
[{"duration":"3h57m59.021170481s","id":2338,"origin":"cscli","scenario":"manual 'enforce_mfa' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"username","type":"enforce_mfa","value":"myuser"}]
```


> Query all decisions of a given type

```bash
▶ curl  -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions\?type\=enforce_mfa                                
[{"duration":"3h57m21.050290118s","id":2338,"origin":"cscli","scenario":"manual 'enforce_mfa' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'","scope":"username","type":"enforce_mfa","value":"myuser"}]

```

## Stream mode

The "streaming mode" of the API (which is actually more like polling) allows for bouncers that are going to fetch on a regular basis an update of the existing decisions. The endpoint is `/decisions/stream` with a single `startup` (boolean) argument. The argument allows to indicate if the bouncer wants the full state of decisions, or only an update since it last pulled.


Given the our state looks like :

```bash
▶ sudo cscli decisions list                                  
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+
|  ID  | SOURCE |   SCOPE:VALUE    |                       REASON                       | ACTION | COUNTRY | AS | EVENTS |     EXPIRATION     | ALERT ID |
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+
| 2337 | cscli  | Range:2.2.3.0/24 | manual 'ban' from                                  | ban    |         |    |      1 | 2h55m26.05271136s  |     1164 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |        |         |    |        |                    |          |
| 2336 | cscli  | Ip:1.2.3.4       | manual 'ban' from                                  | ban    |         |    |      1 | 2h55m19.052706441s |     1163 |
|      |        |                  | '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA' |        |         |    |        |                    |          |
+------+--------+------------------+----------------------------------------------------+--------+---------+----+--------+--------------------+----------+

```

The first call to `/decisions/stream` will look like :

```bash
▶ curl  -s -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions/stream\?startup\=true | jq .            
{
  "deleted": [
    {
      "duration": "-18897h25m52.809576151s",
      "id": 1,
      "origin": "crowdsec",
      "scenario": "crowdsecurity/http-probing",
      "scope": "Ip",
      "type": "ban",
      "value": "123.206.50.249"
    },
    ...
  ],
  "new": [
    {
      "duration": "22h20m11.909761348s",
      "id": 2266,
      "origin": "CAPI",
      "scenario": "crowdsecurity/http-sensitive-files",
      "scope": "ip",
      "type": "ban",
      "value": "91.241.19.122/32"
    },
  ...
  ]
}
```
_note: the initial state will contained passed deleted events (to account for crashes/services restart for example), and the current decisions, both local and those fed from the central API_


!!! info
 
    You might notice that even you are requesting for the initial state, you receive a lot of "deleted" decisions. 
    This is intended to allow you to easily restart the local API without having a desynchronized state with the bouncers.

```bash
▶ curl  -s -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions/stream\?startup\=false | jq .       
{
  "deleted": null,
  "new": null
}
```
_note: Calling the decisions/stream just after will lead to empty results, as no decisions have been added or deleted_



Let's now add a new decision :

```bash
▶ sudo cscli decisions add -i 3.3.3.4                                                   
INFO[0000] Decision successfully added
```

And call our endpoint again :

```bash
▶ curl  -s -H "X-Api-Key: 837be58e22a28738066de1be8f53636b"  http://localhost:8080/v1/decisions/stream\?startup\=false | jq .
{
  "deleted": null,
  "new": [
    {
      "duration": "3h59m57.641708614s",
      "id": 2410,
      "origin": "cscli",
      "scenario": "manual 'ban' from '939972095cf1459c8b22cc608eff85daEb4yoi2wiTD7Y3fA'",
      "scope": "Ip",
      "type": "ban",
      "value": "3.3.3.4"
    }
  ]
}
```


