![Go](https://github.com/crowdsecurity/crowdsec/workflows/Go/badge.svg)
![build-binary-package](https://github.com/crowdsecurity/crowdsec/workflows/build-binary-package/badge.svg)

## About the crowdsec project


Crowdsec is an open-source and lightweight software, that reads logs from different sources (files, streams ...) to parse, normalize and enrich them before comparing them to scenarios.

Scenarios describe more or less specific attacks, ultimately allowing to report malevolent actors and take further action, such as blocking, reporting, throttling etc.

One of the advantages of Crowdsec when compared to other solutions is its crowded aspect : Meta information about detected attacks (source IP, time and triggered scenario) are sent to a central API and then shared amongst all users.

Besides detecting and stopping attacks in real time based on your logs, it allows you to preemptively block known malevolent actors from accessing your information system.

## About this repository

This repository contains the code for the two main components of crowdsec :
 - `crowdsec` : the daemon a-la-fail2ban that can read, parse, enrich and apply heuristis to logs. This is the component in charge of "detecting" the attacks
 - `cscli` : the cli tool mainly used to interact with crowdsec : ban/unban/view current bans, enable/disable parsers and scenarios.

