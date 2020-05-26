

<p align="center"> :warning: <b>Crowdsec BETA </b> :warning: </p>

<p align="center">
<img src="docs/assets/images/crowdsec_logo1.png" alt="CrowdSec" title="CrowdSec" />
</p>


<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/Go/badge.svg">
<img src="https://github.com/crowdsecurity/crowdsec/workflows/build-binary-package/badge.svg">
</p>

<p align="center">
:books: <a href="https://doc.crowdsec.net">Documentation</a>
:diamond_shape_with_a_dot_inside: <a href="https://hub.crowdsec.net">Hub</a>
:speech_balloon: <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

## About the crowdsec project

Crowdsec is an open-source and lightweight software that allows you to detect peers with malevolent behaviors and block them from accessing your systems at various level (infrastructural, system, applicative).

To achieve this, crowdsec reads logs from different sources (files, streams ...) to parse, normalize and enrich them before matching them to threats patterns called scenarios. 

Crowdsec is a modular and plug-able framework, it ships a large variety of well known popular scenarios; users can choose what scenarios they want to be protected from as well as easily adding new custom ones to better fit their environment.

Detected malevolent peers can then be prevented from accessing your resources by deploying [blockers](https://hub.crowdsec.net/browse/#blockers) at various levels (applicative, system, infrastructural) of your stack.

One of the advantages of Crowdsec when compared to other solutions is its crowded aspect : Meta information about detected attacks (source IP, time and triggered scenario) are sent to a central API and then shared amongst all users.

Besides detecting and stopping attacks in real time based on your logs, it allows you to preemptively block known bad actors from accessing your information system.

## Key points

### Fast assisted installation, no technical barrier

<details>
  <summary>User is assisted during setup, providing functional out-of-the-box setup</summary>
  ![](https://github.com/crowdsecurity/crowdsec/blob/improved_readme/docs/assets/images/crowdsec_install.gif)
</details>


### Out of the box detection

![](https://github.com/crowdsecurity/crowdsec/blob/improved_readme/docs/assets/images/out-of-the-box-protection.gif)

> Baseline detection is effective out-of-the-box, no fine-tuning required

### Easy blocker deployment

![](https://github.com/crowdsecurity/crowdsec/blob/improved_readme/docs/assets/images/blocker-installation.gif)

> It's trivial to add blockers to enforce decisions of crowdsec

### Easy dashboard access

![](https://github.com/crowdsecurity/crowdsec/blob/improved_readme/docs/assets/images/cscli-metabase.gif)

> It's easy to deploy a metabase interface to view your data simply with cscli

## About this repository

This repository contains the code for the two main components of crowdsec :
 - `crowdsec` : the daemon a-la-fail2ban that can read, parse, enrich and apply heuristis to logs. This is the component in charge of "detecting" the attacks
 - `cscli` : the cli tool mainly used to interact with crowdsec : ban/unban/view current bans, enable/disable parsers and scenarios.

## :warning: Beta version

Please note that crowdsec is currently in beta version, use with caution !


