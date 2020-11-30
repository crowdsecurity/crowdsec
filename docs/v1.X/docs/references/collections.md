# Collections

Collections are bundle of parsers, scenarios, postoverflows that form a coherent package.
Collections are present in `/etc/crowdsec/collections/` and follow this format :

> `/etc/crowdsec/collections/linux.yaml`

```yaml
#the list of parsers it contains
parsers:
  - crowdsecurity/syslog-logs
  - crowdsecurity/geoip-enrich
  - crowdsecurity/dateparse-enrich
#the list of collections it contains
collections:
  - crowdsecurity/sshd
# the list of postoverflows it contains
# postoverflows:
#   - crowdsecurity/seo-bots-whitelist
# the list of scenarios it contains
# scenarios:
#   - crowdsecurity/http-crawl-non_statics
description: "core linux support : syslog+geoip+ssh"
author: crowdsecurity
tags:
  - linux
```

It mostly exists as a convenience for the user when using the hub.
