`{{cli.bin}}` is the utility that will help you to manage {{crowdsec.name}}. This tools has the following functionalities:

 - [manage bans]({{ cli.ban_doc }}) : list, add, remove ...
 - [backup and restore]({{ cli.backup_doc }}) configuration
 - [display metrics]({{ cli.metrics_doc }})
 - [install]({{ cli.install_doc }}) parsers/scenarios/collections
 - [remove]({{ cli.remove_doc }}) parsers/scenarios/collections
 - [update]({{ cli.update_doc }}) the hub cache
 - [upgrade]({{ cli.upgrade_doc }}) parsers/scenarios/collections
 - [list]({{ cli.list_doc }}) parsers/scenarios/collections
 - [interact with CrowdSec API]({{ cli.api_doc }})

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