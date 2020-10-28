# FREQUENTLY ASKED QUESTIONS

## What is {{v0X.crowdsec.name}} ?

{{v0X.crowdsec.Name}} is a security open-source software. See the [overview](/Crowdsec/v0/#what-is-crowdsec)


## What language is it written in ?

{{v0X.crowdsec.Name}} is written in [Golang](https://golang.org/) 

## What licence is {{v0X.crowdsec.name}} released under ?

{{v0X.crowdsec.Name}} is under [MIT license]({{v0X.crowdsec.url}}/blob/master/LICENSE)

## Which information is sent to the APIs ?

Our aim is to build a strong community that can share malevolent attackers IPs, for that we need to collect the bans triggered locally by each user.

The signal sent by your {{v0X.crowdsec.name}} to the central API only contains only meta-data about the attack :

 - Attacker IP
 - Scenario name
 - Time of start/end of attack

Your logs are not sent to our central API, only meta-data about blocked attacks will be.

## What is the performance impact ?

As {{v0X.crowdsec.name}} only works on logs, it shouldn't impact your production.
When it comes to {{v0X.blockers.name}}, it should perform **one** request to the database when a **new** IP is discovered thus have minimal performance impact.

## How fast is it ?

{{v0X.crowdsec.name}} can easily handle several thousands of events per second on a rich pipeline (multiple parsers, geoip enrichment, scenarios and so on). Logs are a good fit for sharding by default, so it is definitely the way to go if you need to handle higher throughput.

If you need help for large scale deployment, please get in touch with us on the {{v0X.doc.discourse}}, we love challenges ;)

## What backend database does {{v0X.crowdsec.Name}} supports and how to switch ?

Currently (0.3.0), {{v0X.crowdsec.name}} supports SQLite (default) and MySQL databases.
See [backend configuration](/Crowdsec/v0/references/output/#switching-backend-database) for relevant configuration.

SQLite is the default backend as it's suitable for standalone/single-machine setups.
On the other hand, MySQL is more suitable for distributed architectures where blockers across the applicative stack need to access a centralized ban database.

## How to control granularity of actions ? (whitelists, learning etc.)

{{v0X.crowdsec.name}} support both [whitelists]((/Crowdsec/v0/write_configurations/whitelist/) and [learning](/Crowdsec/v0/guide/crowdsec/simulation/) :

 - Whitelists allows you to "discard" events or overflows
 - Learning allows you to simply cancel the decision that is going to be taken, but keep track of it

## How to add whitelists ?

You can follow this [guide](/Crowdsec/v0/write_configurations/whitelist/)

## How to set up proxy ?

Setting up a proxy works out of the box, the [net/http golang library](https://golang.org/src/net/http/transport.go) can handle those environment variables:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `NO_PROXY`

Since {{v0X.cli.name}} uses `sudo`, you just this line in `visudo` after setting up the previous environment variables:

```
Defaults env_keep += "HTTP_PROXY HTTPS_PROXY NO_PROXY"
```

## How to report a bug ?

To report a bug, please open an issue on the [repository]({{v0X.crowdsec.bugreport}})

## What about false positives ?

Several initiatives have been taken to tackle the false positives approach as early as possible :

 - The scenarios published on the hub are tailored to favor low false positive rates
 - You can find [generic whitelists](https://hub.crowdsec.net/author/crowdsecurity/collections/whitelist-good-actors) that should allow to cover most common cases (SEO whitelists, CDN whitelists etc.)
 - The [simulation configuration](/Crowdsec/v0/guide/crowdsec/simulation/) allows you to keep a tight control over scenario and their false positives


## I need some help

Feel free to ask for some help to the {{v0X.doc.community}}.

## How to use crowdsec on raspberry pi OS (formerly known as rasbian) 

Please keep in mind that raspberry pi OS is designed to work on all
raspberry pi versions. Even if the port target is known as armhf, it's
not exactly the same target as the debian named armhf port.

The best way to have a crowdsec version for such an architecture is to
do:
1. install golang (all versions from 1.13 will do)
2. `export GOARCH=arm`
3. `export CGO=1`
4. Update the GOARCH variable in the Makefile to `arm`
5. install the arm gcc cross compilator (On debian the package is gcc-arm-linux-gnueabihf)
6. Compile crowdsec using the usual `make` command


<!-- 

## How to contribute ?

### On {{v0X.crowdsec.Name}}

### On Configurations (Parsers, scenarios)

### On Blockers



## What are common use-cases ?

**TBD**

## What about false positives ?

**TBD**

## How to test if it works ?

**TBD**

## Who are you ?

**TBD**

-->
