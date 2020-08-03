`{{cli.bin}}` is the utility that will help you to manage {{crowdsec.name}}. This tools has the following functionalities:

 - [manage bans]({{ cli.ban_doc }})
 - [backup and restore configuration]({{ cli.backup_doc }})
 - [display metrics]({{ cli.metrics_doc }})
 - [install configurations]({{ cli.install_doc }})
 - [remove configurations]({{ cli.remove_doc }})
 - [update configurations]({{ cli.update_doc }})
 - [upgrade configurations]({{ cli.upgrade_doc }})
 - [list configurations]({{ cli.list_doc }})
 - [interact with CrowdSec API]({{ cli.api_doc }})
 - [manage simulation]({{cli.simulation_doc}})

 Take a look at the [dedicated documentation]({{cli.main_doc}})

## Overview

{{cli.name}} configuration location is `/etc/crowdsec/cscli/`. 

In this folder, we store the {{cli.name}} configuration and the hub cache files.

## Config

The {{cli.name}} configuration is light for now, stored in `/etc/crowdsec/cscli/config`.

```yaml
installdir: /etc/crowdsec/config   # {{crowdsec.name}} configuration location
backend: /etc/crowdsec/plugins/backend # path to the backend plugin used
```

For {{cli.name}} to be able to pull the {{api.topX.htmlname}}, you need a valid API configuration in [api.yaml](/guide/crowdsec/overview/#apiyaml).


## Hub cache

- `.index.json`: The file containing the metadata of all the existing {{collections.htmlname}}, {{parsers.htmlname}} and {{scenarios.htmlname}} stored in the {{hub.htmlname}}.
- `hub/*`: Folder containing all the {{collections.htmlname}}, {{parsers.htmlname}} and {{scenarios.htmlname}} stored in the {{hub.htmlname}}.

This is used to manage configurations from the {{cli.name}}