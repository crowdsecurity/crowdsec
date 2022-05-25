
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="260"/>
</p>
</br>
</br>
</br>
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/tests/badge.svg">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/build/badge.svg">
<a href="https://codecov.io/gh/crowdsecurity/crowdsec">
  <img src="https://codecov.io/gh/crowdsecurity/crowdsec/branch/master/graph/badge.svg?token=CQGSPNY3PT"/>
</a>
<img src="https://goreportcard.com/badge/github.com/crowdsecurity/crowdsec">
<img src="https://img.shields.io/github/license/crowdsecurity/crowdsec">
<img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/AlteredCoder/ed74e50c43e3b17bdfc4d93149f23d37/raw/crowdsec_parsers_badge.json">
<img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/AlteredCoder/ed74e50c43e3b17bdfc4d93149f23d37/raw/crowdsec_scenarios_badge.json">
</p>

<p align="center">
:computer: <a href="https://app.crowdsec.net">Console (WebApp)</a>
:books: <a href="https://doc.crowdsec.net">Documentation</a>
:diamond_shape_with_a_dot_inside: <a href="https://hub.crowdsec.net">Configuration Hub</a>
:speech_balloon: <a href="https://discourse.crowdsec.net">Discourse (Forum)</a>
:speech_balloon: <a href="https://discord.gg/wGN7ShmEE8">Discord (Live Chat)</a>
</p>


:dancer: This is a community driven project, <a href="https://forms.gle/ZQBQcptG2wYGajRX8">we need your feedback</a>.

## <TL;DR>

CrowdSec is a free, modern & collaborative behavior detection engine, coupled with a global IP reputation network. It stacks on fail2ban's philosophy but is IPV6 compatible and 60x faster (Go vs Python), uses Grok patterns to parse logs and YAML scenario to identify behaviors. CrowdSec is engineered for modern Cloud / Containers / VM based infrastructures (by decoupling detection and remediation). Once detected you can remedy threats with various bouncers (firewall block, nginx http 403, Captchas, etc.) while the aggressive IP can be sent to CrowdSec for curation before being shared among all users to further improve everyone's security. See [FAQ](https://doc.crowdsec.net/docs/faq) or read below for more.

## 2 mins install

Installing it through the [Package system](https://doc.crowdsec.net/docs/getting_started/install_crowdsec) of your OS is the easiest way to proceed. 
Otherwise, you can install it from source.

### From package (Debian)

```sh
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt-get update
sudo apt-get install crowdsec
```

### From package (rhel/centos/amazon linux)

```sh
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | sudo bash
sudo yum install crowdsec
```

### From package (FreeBSD)

```
sudo pkg update
sudo pkg install crowdsec
```

### From source

```sh
wget https://github.com/crowdsecurity/crowdsec/releases/latest/download/crowdsec-release.tgz
tar xzvf crowdsec-release.tgz
cd crowdsec-v* && sudo ./wizard.sh -i
```

## :information_source: About the CrowdSec project

Crowdsec is an open-source, lightweight software, detecting peers with aggressive behaviors to prevent them from accessing your systems. Its user friendly design and assistance offers a low technical barrier of entry and nevertheless a high security gain.

The architecture is as follows :

<p align="center">
 <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_architecture.png" alt="CrowdSec" title="CrowdSec"/>
</p>

Once an unwanted behavior is detected, deal with it through a [bouncer](https://hub.crowdsec.net/browse/#bouncers). The aggressive IP, scenario triggered and timestamp are sent for curation, to avoid poisoning & false positives. (This can be disabled). If verified, this IP is then redistributed to all CrowdSec users running the same scenario.

## Outnumbering hackers all together

By sharing the threat they faced, all users are protecting each-others (hence the name Crowd-Security). Crowdsec is designed for modern infrastructures, with its "*Detect Here, Remedy There*" approach, letting you analyse logs coming from several sources in one place and block threats at various levels (applicative, system, infrastructural) of your stack.

CrowdSec ships by default with scenarios (brute force, port scan, web scan, etc.) adapted for most context, but you can easily extend it by picking more of them from the **[HUB](https://hub.crowdsec.net)**. It is also easy to adapt an existing one or create one yourself.

## :point_right: What it is not

CrowdSec is not a SIEM, storing your logs (neither locally nor remotely). Your data are analyzed locally and forgotten.

Signals sent to the curation platform are limited to the very strict minimum: IP, Scenario, Timestamp. They are only used to allow the system to spot new rogue IPs, rule out false positives or poisoning attempts.

## :arrow_down: Install it !

Crowdsec is available for various platforms :

 - [Use our debian repositories](https://doc.crowdsec.net/docs/getting_started/install_crowdsec) or the [official debian packages](https://packages.debian.org/search?keywords=crowdsec&searchon=names&suite=stable&section=all)
 - An [image](https://hub.docker.com/r/crowdsecurity/crowdsec) is available for docker
 - [Prebuilt release packages](https://github.com/crowdsecurity/crowdsec/releases) are also available (suitable for `amd64`)
 - You can as well [build it from source](https://doc.crowdsec.net/docs/user_guides/building)

Or look directly at [installation documentation](https://doc.crowdsec.net/docs/getting_started/install_crowdsec) for other methods and platforms.

## :tada: Key benefits

### Fast assisted installation, no technical barrier

<details open>
  <summary>Initial configuration is automated, providing functional out-of-the-box setup</summary>
  <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_install.gif?raw=true">
</details>

### Out of the box detection

<details>
  <summary>Baseline detection is effective out-of-the-box, no fine-tuning required (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/out-of-the-box-protection.gif?raw=true">
</details>

### Easy bouncer deployment

<details>
  <summary>It's trivial to add bouncers to enforce decisions of crowdsec (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/blocker-installation.gif?raw=true">
</details>

### Easy dashboard access

<details>
  <summary>It's easy to deploy a metabase interface to view your data simply with cscli (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/cscli-metabase.gif?raw=true">
</details>

### Hot & Cold logs

<details>
  <summary>Process cold logs, for forensic, tests and chasing false-positives & false negatives (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/forensic-mode.gif?raw=true">
</details>


## 📦 About this repository

This repository contains the code for the two main components of crowdsec :
 - `crowdsec` : the daemon a-la-fail2ban that can read, parse, enrich and apply heuristics to logs. This is the component in charge of "detecting" the attacks
 - `cscli` : the cli tool mainly used to interact with crowdsec : ban/unban/view current bans, enable/disable parsers and scenarios.


## Contributing

If you wish to contribute to the core of crowdsec, you are welcome to open a PR in this repository.

If you wish to add a new parser, scenario or collection, please open a PR in the [hub repository](https://github.com/crowdsecurity/hub).

If you wish to contribute to the documentation, please open a PR in the [documentation repository](http://github.com/crowdsecurity/crowdsec-docs).
