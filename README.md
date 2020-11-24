

<p align="center"> :warning: <b>Crowdsec BETA </b> :warning: </p>

<p align="center">
<img src="docs/assets/images/crowdsec_logo1.png" alt="CrowdSec" title="CrowdSec" />
</p>


<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/tests/badge.svg">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/build/badge.svg">
<a href='https://coveralls.io/github/crowdsecurity/crowdsec?branch=master'><img src='https://coveralls.io/repos/github/crowdsecurity/crowdsec/badge.svg?branch=master' alt='Coverage Status' /></a>
<img src="https://goreportcard.com/badge/github.com/crowdsecurity/crowdsec">
<img src="https://img.shields.io/github/license/crowdsecurity/crowdsec">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/Hub-CI/badge.svg">
</p>

<p align="center">
:books: <a href="https://doc.crowdsec.net">Documentation</a>
:diamond_shape_with_a_dot_inside: <a href="https://hub.crowdsec.net">Hub</a>
:speech_balloon: <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

## About the crowdsec project

Crowdsec is an open-source and lightweight software that allows you to detect peers with malevolent behaviors and block them from accessing your systems at various levels (infrastructural, system, applicative).

To achieve this, Crowdsec reads logs from different sources (files, streams ...) to parse, normalize and enrich them before matching them to threats patterns aka scenarios. 

Crowdsec is a modular and plug-able framework, it ships a large variety of well known popular scenarios; users can choose what scenarios they want to be protected from as well as easily add new custom ones to better fit their environment.

Detected malevolent peers can then be prevented from accessing your resources by deploying [bouncers](https://hub.crowdsec.net/browse/#bouncers) at various levels (applicative, system, infrastructural) of your stack.

One of the advantages of Crowdsec when compared to other solutions is its crowded aspect : Meta information about detected attacks (source IP, time and triggered scenario) are sent to a central API and then shared amongst all users.

Besides detecting and stopping attacks in real time based on your logs, it allows you to preemptively block known bad actors from accessing your information system.


## Install it !

Find the [latest release](https://github.com/crowdsecurity/crowdsec/releases)

Ensure you have dependencies :
<details open>
  <summary>for Debian based distributions</summary>

```bash
apt-get install bash gettext whiptail curl wget
```
</details>

<details>
  <summary>for RedHat based distributions</summary>

```bash
yum install bash gettext newt curl wget
 ```
</details>

```bash
curl -s https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest | grep browser_download_url| cut -d '"' -f 4  | wget -i -
tar xvzf crowdsec-release.tgz
cd crowdsec-v*
sudo ./wizard.sh -i
```



## Key points

### Fast assisted installation, no technical barrier

<details open>
  <summary>User is assisted during setup, providing functional out-of-the-box setup</summary>
  <img src="https://github.com/crowdsecurity/crowdsec/blob/master/docs/assets/images/crowdsec_install.gif">
</details>

### Out of the box detection

<details>
  <summary>Baseline detection is effective out-of-the-box, no fine-tuning required (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec/blob/master/docs/assets/images/out-of-the-box-protection.gif">
</details>

### Easy blocker deployment

<details>
  <summary>It's trivial to add bouncers to enforce decisions of crowdsec (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec/blob/master/docs/assets/images/blocker-installation.gif">
</details>

### Easy dashboard access

<details>
  <summary>It's easy to deploy a metabase interface to view your data simply with cscli (click to expand)</summary>
  <img src="https://github.com/crowdsecurity/crowdsec/blob/master/docs/assets/images/cscli-metabase.gif">
</details>

## About this repository

This repository contains the code for the two main components of crowdsec :
 - `crowdsec` : the daemon a-la-fail2ban that can read, parse, enrich and apply heuristis to logs. This is the component in charge of "detecting" the attacks
 - `cscli` : the cli tool mainly used to interact with crowdsec : ban/unban/view current bans, enable/disable parsers and scenarios.

## :warning: Beta version

Please note that crowdsec is currently in beta version, use with caution !


