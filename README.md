
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="260"/>
</p>
</br>
</br>
</br>
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/actions/workflows/go-tests.yml/badge.svg">
<img src="https://github.com/crowdsecurity/crowdsec/actions/workflows/bats.yml/badge.svg">
<a href="https://codecov.io/gh/crowdsecurity/crowdsec">
  <img src="https://codecov.io/gh/crowdsecurity/crowdsec/branch/master/graph/badge.svg?token=CQGSPNY3PT"/>
</a>
<img src="https://goreportcard.com/badge/github.com/crowdsecurity/crowdsec">
<a href="https://pkg.go.dev/github.com/crowdsecurity/crowdsec"><img src="https://pkg.go.dev/badge/github.com/crowdsecurity/crowdsec.svg" alt="Go Reference"></a>
<img src="https://img.shields.io/github/license/crowdsecurity/crowdsec">
<img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/AlteredCoder/ed74e50c43e3b17bdfc4d93149f23d37/raw/crowdsec_parsers_badge.json">
<img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/AlteredCoder/ed74e50c43e3b17bdfc4d93149f23d37/raw/crowdsec_scenarios_badge.json">
<a href="https://hub.docker.com/r/crowdsecurity/crowdsec">
  <img src="https://img.shields.io/docker/pulls/crowdsecurity/crowdsec?logo=docker">
</a>
<a href="https://discord.com/invite/crowdsec">
  <img src="https://img.shields.io/discord/921520481163673640?label=Discord&logo=discord">
</a>
</p>

<p align="center">
:computer: <a href="https://app.crowdsec.net">Console (WebApp)</a>
:books: <a href="https://doc.crowdsec.net">Documentation</a>
:diamond_shape_with_a_dot_inside: <a href="https://hub.crowdsec.net">Configuration Hub</a>
:speech_balloon: <a href="https://discourse.crowdsec.net">Discourse (Forum)</a>
:speech_balloon: <a href="https://discord.gg/crowdsec">Discord (Live Chat)</a>
</p>


:dancer: This is a community-driven project, <a href="https://forms.gle/ZQBQcptG2wYGajRX8">we need your feedback</a>.

## <TL;DR>

CrowdSec is a open-source, modern, and collaborative behavior detection engine that works with a global IP reputation network. It builds on the principles of fail2ban but offers IPV6 compatibility. CrowdSec uses Grok patterns to analyze logs and YAML scenarios to detect malicious behavior.

## :tada: Benefits

- **Fast assisted installation, no technical barrier**: The initial configuration is automated, giving you a ready-to-use setup for common services right out of the box.
- **Crowdsourced protection**: Once you join the CrowdSec community, you are automatically protected by the **Community Blocklist**, which blocks known malicious IP addresses.
- **Observability**: CrowdSec offers a [SaaS console](https://app.crowdsec.net/signup) that lets you visualize your data and manage your deployments. Additionally, we provide a Prometheus metrics endpoint for monitoring.
- **Compiled Code**: CrowdSec is written in Go and is compiled into a static binary. This eliminates the need for external runtime dependencies, ensuring quick performance and easy deployment across various environments.

## Installation

Checkout our various getting started guides depending on your platform :
- [Linux](https://docs.crowdsec.net/u/getting_started/installation/linux)
- [FreeBSD](https://docs.crowdsec.net/u/getting_started/installation/freebsd)
- [Windows](https://docs.crowdsec.net/u/getting_started/installation/windows)
- [Docker/Podman](https://docs.crowdsec.net/u/getting_started/installation/docker)
- [Kubernetes](https://docs.crowdsec.net/u/getting_started/installation/kubernetes)

We have many more guides on the [documentation](https://docs.crowdsec.net/u/getting_started/installation/linux) so if the above doesn't fit your needs, please check them out.

### From source

We recommend using the above installation options over from source, as you will benefit from automatic updates and a more streamlined experience. 

```sh
wget https://github.com/crowdsecurity/crowdsec/releases/latest/download/crowdsec-release.tgz
tar xzvf crowdsec-release.tgz
cd crowdsec-v* && sudo ./wizard.sh -i
```

## :information_source: About the CrowdSec project

CrowdSec is an open-source, lightweight software that detects patterns of malicious behavior to block bad actors from accessing your systems. With its user-friendly design and support, it provides a low technical barrier to entry while delivering a high level of security.

The architecture is as follows :

<p align="center">
 <img src="https://www.crowdsec.net/_next/image?url=%2F_next%2Fstatic%2Fmedia%2Fapi-diagram.512bc091.png&w=2048&q=90" alt="CrowdSec" title="CrowdSec"/>
</p>

When unwanted behavior is detected, you can address it using a [Remediation Component](https://hub.crowdsec.net/remediation-components).

## Outnumbering hackers all together

By sharing the threats you encounter, CrowdSec users help protect each other—hence the name Crowd-Security. Designed for modern infrastructures, CrowdSec follows a "*Detect Here, Remedy There*" approach, allowing you to analyze logs from multiple sources and block threats at different levels of your stack (application, system, or infrastructure).

CrowdSec comes with default scenarios, such as brute force, port scans, and web scans, suitable for most environments. You can easily extend these scenarios by choosing more from the **[HUB](https://hub.crowdsec.net)** or by adapting existing ones or creating your own.

## :point_right: What it is not

CrowdSec is not a SIEM; it doesn't store your logs either locally or remotely. Logs are analyzed locally, and only signals are sent to the curation platform.

The signals shared with the curation platform are limited to just a few key data points:
- IP Address
- Scenario
- Timestamp

These signals are used solely to detect malicious IPs and to eliminate false positives or malicious manipulation attempts to influence the global reputation system.

You can read more about the [CrowdSec data model](https://www.crowdsec.net/our-data).

## 📦 About this repository

This repository contains the code for the two main components of CrowdSec:

- **`crowdsec`**: The daemon, similar to fail2ban, that reads, parses, enriches, and applies heuristics to logs. This is the component responsible for "detecting" attacks.

- **`cscli`**: The command-line tool used primarily to interact with CrowdSec. It allows you to ban/unban IPs, view current bans, and enable/disable parsers and scenarios.

## Contributing

If you'd like to contribute to the core of CrowdSec, you're welcome to open a pull request (PR) in the main repository.

To add a new parser, scenario, or collection, please submit a PR to the [Hub repository](https://github.com/crowdsecurity/hub).

For contributions to the documentation, open a PR in the [Documentation repository](http://github.com/crowdsecurity/crowdsec-docs).
