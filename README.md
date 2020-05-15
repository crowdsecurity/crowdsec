![Go](https://github.com/crowdsecurity/crowdsec/workflows/Go/badge.svg)
![build-binary-package](https://github.com/crowdsecurity/crowdsec/workflows/build-binary-package/badge.svg)

# CrowdSec project

Please see [terminology](#terminology) if you're new to the projetct.

## Foreword

This repository contains the code for the two main components of crowdsec :
 - `crowdsec` : the daemon a-la-fail2ban that can read, parse, enrich and apply heuristis to logs. This is the component in charge of "detecting" the attacks
 - `cscli` : the cli tool mainly used to interact with crowdsec : ban/unban/view current bans, enable/disable parsers and scenarios.

## Plugins

The plugins are in charge of blocking that Ip/Ranges that have been tagged as malevolent.
They do so by querying a sqlite database when they see a new IP. This SQLite database is being fed by crowdsec.
The following plugins are available :
 - `netfilter-plugin` : an iptables/ipset service that can be deployed by the wizard. it will allow to ban IP/Ranges as you would do with iptables.
 - `nginx-plugin` : a LUA connector for nginx that can be deployed by the wizard. it will allow to ban ip/ranges at the applicative level (ie. more suitable than iptables if your website is behind a CDN).
 - `wordpress-plugin` : a Wordpress/php module that can be deployed in Wordpress to block the requests at the applicative level. (it comes as a library for easy re-use).
 



# Software architecture


![global crowdsec architecture](./doc/img/crowdsec-global.png)


**NOTE** the API part isn't enabled by default.

# Build

**To build crowdsec you need golang >= 1.13.**
To build binaries :

```
$ make build
```
 
# Installation

## With the wizard
 
 The wizard is here is significatively improve the user experience, and aims at providing a _next-next-next-finish_ installer that should work out of the box on most linux flavored systems.

 The wizard will help you in the following steps :
  - detect running services
  - detect their log files(by default in `/etc/crowdsec/`) 
  - suggest collections/scenarios according to the detect services
  - deploy crowdsec service
  - deploy plugins
 
 ```bash
 $ make build
 $ sudo ./wizard.sh -i
 ```
 
 and you're done !
 

## Without the wizard

> You man of little faith

You can install crowdsec and its cli without the wizard :

```bash
$ make build
$ make systemd
```

**NOTE** if you install without the wizard, it will be your responsability to configure the acquisition (which file to read for which service) and to deploy scenarios and parsers (how to parse logs, and which scenarios should be applied to which services).

## After the installation

Services are deployed as systemd units : 
 - `crowdsec` is the detection component
 - `crowdsec-netfilter` is the netfilter plugin
 - the nginx, wordpress etc. plugins usually are ran inside said service (ie. nginx plugin is a LUA script, wordpress plugin is a php module)
 - `cscli` is deployed in standard path.

```bash
$ sudo systemctl status crowdsec
# stop the netfilter plugin. If you didn't install other plugins, decisions won't be 'applied' anymore unless you start it again.
$ sudo systemctl stop crowdsec-netfilter
```

# Configuration

crowdsec relies on the following configuration files (by default in `/etc/crowdsec/`) :

 - default.yaml : The main configuration of crowdsec, you will find here informations about logging, path to sqlite DB etc.
 - acquis.yaml : Describes the files that will be read (a-la `tail -f`) and which type of logs to expect from it
 - api.yaml : url & token for api push and pulls (pushes **signal occurences** and fetchs **crowd-sourced reputation**)
 - profiles.yaml : (you shouldn't modify this one) Describes in which condition crowdsec should insert a ban decision in database. It's usually because a scenario has a `remediation: true` flag in its tags.

However, the "real" configuration of crowdsec relies on the collections of scenarios and parsers that you have deployed.
Those are deployed / upgraded / removed (ideally) with `cscli`, see [its dedicated documentation](./cmd/crowdsec-cli/doc/cscli.md)

If you used the wizard, chances are that you don't have anything specific to configure.

# Usage / FAQ

[See `cscli`dedicated documentation](./cmd/crowdsec-cli/doc/cscli.md)

## stop the netfilter plugin

**note** when netfilter plugin is disabled, no bans will be applied if no other plugins are enabled.

```
#view netfilter logs
$ journalctl -u -f crowdsec-netfilter
#stop service
$ systemctl stop crowdsec-netfilter
```

## view/add/remove bans

```
# cscli  ban list
INFO[0000] 38 non-expired ban applications              
+-----------------+---------------+--------------------+--------+---------+--------------------------------+--------------+--------------------+
|     SOURCE      |   SCENARIO    | CURRENT BANS COUNT | ACTION | COUNTRY |               AS               | EVENTS COUNT |     EXPIRATION     |
+-----------------+---------------+--------------------+--------+---------+--------------------------------+--------------+--------------------+
| 37.195.50.41    | ssh_user_enum |                  1 | ban    | RU      | 31200 Novotelecom Ltd          |            4 | 3h59m56.337435741s |
| 159.203.143.58  | ssh_user_enum |                  1 | ban    | US      | 14061 DigitalOcean, LLC        |            4 | 3h59m55.585257629s |
...
# cscli  ban  add range 37.139.4.0/24 10m spam
# cscli  ban  add ip 37.139.4.123 10m spam
```

# Terminology

 - **crowdsec** : the daemon that reads log files, parses logs and triggers scenarios, alerts and bans.
 - **crowdsec database** : a local file that contains at a given time the list of banned ip/ranges.
 - **plugin** : a software component that can interact with crowdsec database to block/delay attackers.
 - **parser** : a configuration file that allows crowdsec to 'understand' a specific log file format. Each service will generally require its own parser (nginx, apache, sshd, mysql etc.). parsers are usually found on the **hub** and downloaded via the **cli**.
 - **scenario** : a leakybucket description that allows to detect a specific attack : _more that 5 failed ssh authentication attempts from the same IP within less than 20 seconds is a ssh bruteforce and should be punished_
 - **signal** : the information resulting from a scenario being triggered, this information is shared amongst participants and will lead to consensus : _users A, B, C, D all reported that ip 1.2.3.4 targetted them with a ssh bruteforce_
 - **bucket**, **bucket overflow** : a more technical term referring to a scenario being triggered.
 - **hub** : the portal on which users can find, share and publish parsers and scenarios.
 - **cli** : the `cscli` tool.

# Making a release

 - release-drafter maintains a draft release up-to-date with MRs
 - when you publish the release with the "pre-release" flag, it's going to launch action to add the built release package to release.
 - once extra manual steps are done, you can remove the "pre-release" flag from published release "and voila"
 

