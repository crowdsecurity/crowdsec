
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="260"/>
</p>
</br>
</br>
</br>
<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec/actions/workflows/go-tests.yml/badge.svg">
<img src="https://github.com/crowdsecurity/crowdsec/actions/workflows/bats.yml/badge.svg">
<img src="https://img.shields.io/github/license/crowdsecurity/crowdsec">
<a href="https://discord.com/invite/crowdsec">
  <img src="https://img.shields.io/discord/921520481163673640?label=Discord&logo=discord">
</a>
<img src="https://img.shields.io/twitter/follow/Crowd_Security?style=social">
</p>

_CrowdSec is an open-source and participative security solution offering crowdsourced server detection and protection against malicious IPs. Detect and block with our Security Engine, contribute to the network, and enjoy our real-time community blocklist._

<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/simplified_SE_overview.svg" alt="CrowdSec schema" title="CrowdSec Schema"/>
</p>

## Features & Advantages

### Versatile Security Engine

[CrowdSec Security Engine](https://doc.crowdsec.net/docs/next/intro/) is an all-in-one [IDS/IPS](https://doc.crowdsec.net/docs/next/log_processor/intro) and [WAF](https://doc.crowdsec.net/docs/next/appsec/intro).

It detects bad behaviors by analyzing log sources and HTTP requests, and allows active remedation thanks to the [Remediation Components](https://doc.crowdsec.net/u/bouncers/intro).

[Detection rules are available on our hub](https://hub.crowdsec.net) under MIT license.

### CrowdSec Community Blocklist

<a href="https://doc.crowdsec.net/docs/next/central_api/community_blocklist">

The "Community Blocklist" is a curated list of IP addresses identified as malicious by CrowdSec. The Security Engine proactively block the IP addresses of this blocklist, preventing malevolent IPs from reaching your systems.

[![CrowdSec Community Blocklist](https://doc.crowdsec.net/assets/images/data_insights-1e7678f47cb672122cc847d068b6eadf.png)](https://doc.crowdsec.net/docs/next/central_api/community_blocklist)

</a>

### Console - Monitoring & Automation of your security stack

[![CrowdSec Console](https://doc.crowdsec.net/assets/images/visualizer-summary-c8087e2eaef65d110bad6a7f274cf953.png)](https://doc.crowdsec.net/u/console/intro)

### Multiple Platforms support

[![Multiple Platforms support](https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/supported_platforms.png)](https://doc.crowdsec.net/)


## Outnumbering hackers all together

By sharing the threat they faced, all users are protecting each-others (hence the name Crowd-Security). Crowdsec is designed for modern infrastructures, with its "*Detect Here, Remedy There*" approach, letting you analyze logs coming from several sources in one place and block threats at various levels (applicative, system, infrastructural) of your stack.

CrowdSec ships by default with scenarios (brute force, port scan, web scan, etc.) adapted for most contexts, but you can easily extend it by picking more of them from the **[HUB](https://hub.crowdsec.net)**. It is also easy to adapt an existing one or create one yourself.

## Installation

<!-- make this an image with link ?-->

[Follow our documentation to install CrowdSec in a few minutes on Linux, Windows, Docker, OpnSense, Kubernetes, and more.](https://doc.crowdsec.net/)


## Resources

 - [Console](https://app.crowdsec.net): Supercharge your CrowdSec setup with visualization, management capabilities, extra blocklists and premium features.
 - [Documentation](https://doc.crowdsec.net): Learn how to exploit your CrowdSec setup to deter more attacks.
 - [Discord](https://discord.gg/crowdsec): A question or a suggestion? This is the place.
 - [Hub](https://hub.crowdsec.net): Improve your stack protection, find the relevant remediation components for your infrastructure.
 - [CrowdSec Academy](https://academy.crowdsec.net/): Learn and grow with our courses.
 - [Corporate Website](https://crowdsec.net): For everything else.
