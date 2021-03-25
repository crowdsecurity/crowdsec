# Overview

`{{v1X.cli.name}}` is the utility that will help you to manage {{v1X.crowdsec.name}}. This tool has the following functionalities:

 - manage [decisions](/Crowdsec/v1/cscli/cscli_decisions/) and [alerts](/Crowdsec/v1/cscli/cscli_alerts/) : This is how you monitor ongoing remediation and detections
 - manage configurations such as [collections](/Crowdsec/v1/cscli/cscli_collections/), [parsers](/Crowdsec/v1/cscli/cscli_parsers/), [scenarios](/Crowdsec/v1/cscli/cscli_scenarios/) : This is how you install/update {{v1X.crowdsec.htmname}}'s detection capabilities and manage whitelists
 - interact with the [hub](/Crowdsec/v1/cscli/cscli_hub/) to find new configurations or update existing ones
 - manage local api (LAPI) [bouncers](/Crowdsec/v1/cscli/cscli_bouncers/) and [machines](/Crowdsec/v1/cscli/cscli_machines/) : This allows you to manage LAPI credentials, this is how you make {{v1X.crowdsec.htmname}} and bouncers comunicate
 - observe crowdsec via [metrics](/Crowdsec/v1/cscli/cscli_metrics/) or the [dashboard](/Crowdsec/v1/cscli/cscli_dashboard/) : This is how you gain real-time observability 
 - manage [simulation](/Crowdsec/v1/cscli/cscli_simulation/) configurations, allowing you to disable/modify remediation triggered by specific scenarios


Take a look at the [dedicated documentation](/Crowdsec/v1/cscli/cscli)

!!! tips
    You can enable `cscli` auto completion in `bash` or `zsh`.

    You can find `cscli completion` documentation [here](/Crowdsec/v1/cscli/cscli_completion/).

# Configuration

`{{v1X.cli.name}}` shares the configuration file of {{v1X.crowdsec.name}}, usually in `/etc/crowdsec/config.yaml`
