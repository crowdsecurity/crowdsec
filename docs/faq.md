# FREQUENTLY ASKED QUESTIONS

## What is {{v1X.crowdsec.name}} ?

{{v1X.crowdsec.Name}} is a security open-source software. See the [overview](/#what-is-crowdsec).

## I've installed crowdsec, it detects attacks but doesn't block anything ?!

Yes, {{v1X.crowdsec.Name}} is in charge of detecting attacks, and {{v1X.bouncers.htmlname}} are applying decisions.
If you want to block the detected IPs, you should deploy a bouncer, such as the ones found on the [hub](https://hub.crowdsec.net/browse/#bouncers) !


## What language is it written in ?

{{v1X.crowdsec.Name}} is written in [Golang](https://golang.org/).

## What licence is {{v1X.crowdsec.name}} released under ?

{{v1X.crowdsec.Name}} is under [MIT license]({{v1X.crowdsec.url}}/blob/master/LICENSE).

## Which information is sent to the APIs ?

Our aim is to build a strong community that can share malevolent attackers IPs, for that we need to collect the bans triggered locally by each user.

The signal sent by your {{v1X.crowdsec.name}} to the central API only contains only meta-data about the attack :

 - Attacker IP
 - Scenario name
 - Time of start/end of attack

Your logs are not sent to our central API, only meta-data about blocked attacks will be.


When pulling block-lists from the platform, the following information is shared as well :

 - list of [upstream installed scenarios](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=CAPI#/watchers/post_metrics)
 - list of [bouncers & number of machines](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=CAPI#/watchers/post_metrics)

## What is the performance impact ?

As {{v1X.crowdsec.name}} only works on logs, it shouldn't impact your production.
When it comes to {{v1X.bouncers.name}}, it should perform **one** request to the database when a **new** IP is discovered thus have minimal performance impact.

## How fast is it ?

{{v1X.crowdsec.name}} can easily handle several thousands of events per second on a rich pipeline (multiple parsers, geoip enrichment, scenarios and so on). Logs are a good fit for sharding by default, so it is definitely the way to go if you need to handle higher throughput.

If you need help for large scale deployment, please get in touch with us on the {{v1X.doc.discourse}}, we love challenges ;)

## What backend database does {{v1X.crowdsec.Name}} supports and how to switch ?

{{v1X.crowdsec.name}} versions (under v0.3.X) supports SQLite (default) and MySQL databases.
See [backend configuration](/Crowdsec/v0/references/output/#switching-backend-database) for relevant configuration. MySQL here is more suitable for distributed architectures where bouncers across the applicative stack need to access a centralized ban database.

{{v1X.crowdsec.name}} versions (after v1) supports SQLite (default), MySQL and PostgreSQL databases.
See [databases configuration](/Crowdsec/v1/user_guide/database/) for relevant configuration. Thanks to the {{v1X.lapi.Htmlname}}, distributed architectures are resolved even with sqlite database.

SQLite by default as it's suitable for standalone/single-machine setups.

## How to control granularity of actions ? (whitelists, simulation etc.)

{{v1X.crowdsec.name}} support both [whitelists](/Crowdsec/v1/write_configurations/whitelist/) and [simulation](/Crowdsec/v1/references/simulation/) :

 - Whitelists allows you to "discard" events or overflows
 - Simulation allows you to simply cancel the decision that is going to be taken, but keep track of it

 {{v1X.profiles.htmlname}} allows you to control which decision will be applied to which alert.

## How to know if my setup is working correctly ? Some of my logs are unparsed, is it normal ?

Yes, crowdsec parsers only parse the logs that are relevant for scenarios :)

Take a look at `cscli metrics` [and understand what do they mean](/Crowdsec/v1/getting_started/crowdsec-tour/#reading-metrics) to know if your setup is correct.


## How to add whitelists ?

You can follow this [guide](/Crowdsec/v1/write_configurations/whitelist/)

## How to set up proxy ?

Setting up a proxy works out of the box, the [net/http golang library](https://golang.org/src/net/http/transport.go) can handle those environment variables:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `NO_PROXY`

For example:

```
export HTTP_PROXY=http://<proxy_url>:<proxy_port>
```
### Systemd variable
On Systemd devices you have to set the proxy variable in the environment section for the CrowdSec service. To avoid overwriting the service file during an update, a folder is created in `/etc/systemd/system/crowdsec.service.d` and a file in it named `http-proxy.conf`. The content for this file should look something like this:
```
[Service]
Environment=HTTP_PROXY=http://myawesomeproxy.com:8080
Environment=HTTPS_PROXY=https://myawesomeproxy.com:443
```
After this change you need to reload the systemd daemon using:
`systemctl daemon-reload`

Then you can restart CrowdSec like this:
`systemctl restart crowdsec`

### Sudo
If you use `sudo` {{v1X.cli.name}}, just add this line in `visudo` after setting up the previous environment variables:

```
Defaults        env_keep += "HTTP_PROXY HTTPS_PROXY NO_PROXY"
```

## How to report a bug ?

To report a bug, please open an issue on the [repository]({{v1X.crowdsec.bugreport}}).

## What about false positives ?

Several initiatives have been taken to tackle the false positives approach as early as possible :

 - The scenarios published on the hub are tailored to favor low false positive rates
 - You can find [generic whitelists](https://hub.crowdsec.net/author/crowdsecurity/collections/whitelist-good-actors) that should allow to cover most common cases (SEO whitelists, CDN whitelists etc.)
 - The [simulation configuration](/Crowdsec/v1/references/simulation/) allows you to keep a tight control over scenario and their false positives


## I need some help

Feel free to ask for some help to the {{v1X.doc.discourse}} or directly in the {{v1X.doc.gitter}} chat.

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


## How to have a dashboard without docker

`cscli dashboard` rely on [`docker`](https://docs.docker.com/) to launch the `metabase` image. If `docker` is not installed on your machine, here are the step to follow to get crowdsec dashboards without docker:

- Download Metabase `jar` file. See [metabase documentation](https://www.metabase.com/docs/latest/operations-guide/running-the-metabase-jar-file.html).
- Download the `metabase.db` folder from Crowdsec [here](https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/metabase_sqlite.zip).
- Unzip the `zip` file: 

```bash
unzip metabase_sqlite.zip
```

- Make crowdsec database reachable from metabase :

```bash
sudo mkdir /metabase-data/
sudo ln -s /var/lib/crowdsec/data/crowdsec.db /metabase-data/crowdsec.db
```

- Launch Metabase: 

```bash
sudo MB_DB_TYPE=h2 MB_DB_FILE=<absolute-path>/metabase.db/metabase.db java -jar metabase.jar
```

!!! warning
        The default username is `crowdsec@crowdsec.net` and the default password is `!!Cr0wdS3c_M3t4b4s3??`. Please update the password when you will connect to metabase for the first time

You can as well check [liberodark's helper script for it](https://github.com/liberodark/crowdsec-dashboard).

## How to configure crowdsec/cscli to use Tor


It is possible to configure `cscli` and `crowdsec` to use [tor](https://www.torproject.org/) to anonymously interact with our API.
All (http) requests made to the central API to go through the [tor network](https://www.torproject.org/).


With tor installed, setting `HTTP_PROXY` and `HTTPS_PROXY` environment variables to your socks5 proxy will do the trick.


### Running the wizard with tor

```bash
$ sudo HTTPS_PROXY=socks5://127.0.0.1:9050 HTTP_PROXY=socks5://127.0.0.1:9050  ./wizard.sh --bininstall
```

!!! warning
        Do not use the wizard in interactive (`-i`) mode if you're concerned, as it will start the service at the end of the setup, leaking your IP address.


### Edit crowdsec systemd unit to push/pull via tor

```bash
[Service]
Environment="HTTPS_PROXY=socks5://127.0.0.1:9050"
Environment="HTTP_PROXY=socks5://127.0.0.1:9050"
...
```
### Using cscli via tor

```bash
$ sudo HTTP_PROXY=socks5://127.0.0.1:9050 HTTPS_PROXY=socks5://127.0.0.1:9050 cscli capi register
```




<!-- 

## What are common use-cases ?

**TBD**

## What about false positives ?

**TBD**

## How to test if it works ?

**TBD**

## Who are you ?

**TBD**

-->
