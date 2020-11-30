`{{v0X.cli.bin}}` is the utility that will help you to manage {{v0X.crowdsec.name}}. This tools has the following functionalities:

 - [manage bans]({{v0X. cli.ban_doc }})
 - [backup and restore configuration]({{v0X. cli.backup_doc }})
 - [display metrics]({{v0X. cli.metrics_doc }})
 - [install configurations]({{v0X. cli.install_doc }})
 - [remove configurations]({{v0X. cli.remove_doc }})
 - [update configurations]({{v0X. cli.update_doc }})
 - [upgrade configurations]({{v0X. cli.upgrade_doc }})
 - [list configurations]({{v0X. cli.list_doc }})
 - [interact with CrowdSec API]({{v0X. cli.api_doc }})
 - [manage simulation]({{v0X.cli.simulation_doc}})

 Take a look at the [dedicated documentation]({{v0X.cli.main_doc}})

## Overview

{{v0X.cli.name}} configuration location is `/etc/crowdsec/cscli/`. 

In this folder, we store the {{v0X.cli.name}} configuration and the hub cache files.

## Config

The {{v0X.cli.name}} configuration is light for now, stored in `/etc/crowdsec/cscli/config`.

```yaml
installdir: /etc/crowdsec/config   # {{v0X.crowdsec.name}} configuration location
backend: /etc/crowdsec/plugins/backend # path to the backend plugin used
```

For {{v0X.cli.name}} to be able to pull the {{v0X.api.topX.htmlname}}, you need a valid API configuration in [api.yaml](/Crowdsec/v0/guide/crowdsec/overview/#apiyaml).


## Hub cache

- `.index.json`: The file containing the metadata of all the existing {{v0X.collections.htmlname}}, {{v0X.parsers.htmlname}} and {{v0X.scenarios.htmlname}} stored in the {{v0X.hub.htmlname}}.
- `hub/*`: Folder containing all the {{v0X.collections.htmlname}}, {{v0X.parsers.htmlname}} and {{v0X.scenarios.htmlname}} stored in the {{v0X.hub.htmlname}}.

This is used to manage configurations from the {{v0X.cli.name}}