`{{v1X.cli.bin}}` is the utility that will help you to manage {{v1X.crowdsec.name}}. This tools has the following functionalities:

 - [manage bans]({{v1X. cli.ban_doc }})
 - [backup and restore configuration]({{v1X. cli.backup_doc }})
 - [display metrics]({{v1X. cli.metrics_doc }})
 - [install configurations]({{v1X. cli.install_doc }})
 - [remove configurations]({{v1X. cli.remove_doc }})
 - [update configurations]({{v1X. cli.update_doc }})
 - [upgrade configurations]({{v1X. cli.upgrade_doc }})
 - [list configurations]({{v1X. cli.list_doc }})
 - [interact with CrowdSec API]({{v1X. cli.api_doc }})
 - [manage simulation]({{v1X.cli.simulation_doc}})

 Take a look at the [dedicated documentation]({{v1X.cli.main_doc}})

## Overview

{{v1X.cli.name}} configuration location is `/etc/crowdsec/cscli/`. 

In this folder, we store the {{v1X.cli.name}} configuration and the hub cache files.

## Config

The {{v1X.cli.name}} configuration is light for now, stored in `/etc/crowdsec/cscli/config`.

```yaml
installdir: /etc/crowdsec/config   # {{v1X.crowdsec.name}} configuration location
backend: /etc/crowdsec/plugins/backend # path to the backend plugin used
```

For {{v1X.cli.name}} to be able to pull the {{v1X.api.topX.htmlname}}, you need a valid API configuration in [api.yaml](/Crowdsec/v1/guide/crowdsec/overview/#apiyaml).


## Hub cache

- `.index.json`: The file containing the metadata of all the existing {{v1X.collections.htmlname}}, {{v1X.parsers.htmlname}} and {{v1X.scenarios.htmlname}} stored in the {{v1X.hub.htmlname}}.
- `hub/*`: Folder containing all the {{v1X.collections.htmlname}}, {{v1X.parsers.htmlname}} and {{v1X.scenarios.htmlname}} stored in the {{v1X.hub.htmlname}}.

This is used to manage configurations from the {{v1X.cli.name}}