# Installation

Fetch {{crowdsec.name}}'s latest version [here]({{crowdsec.download_url}}).

```bash
tar xvzf crowdsec-release.tgz
```
```bash
cd crowdsec-v0.X.X
```

A {{wizard.name}} is provided to help you deploy {{crowdsec.name}} and {{cli.name}}.

## Using the interactive wizard

```
sudo {{wizard.bin}} -i
```

![crowdsec](../assets/images/crowdsec_install.gif)

The {{wizard.name}} is going to guide you through the following steps :

 - detect services that are present on your machine
 - detect selected services logs
 - suggest collections (parsers and scenarios) to deploy
 - deploy & configure {{crowdsec.name}} in order to watch selected logs for selected scenarios
 
The process should take less than a minute, [please report if there are any issues]({{wizard.bugreport}}).

You are then ready to [take a tour](/getting_started/crowdsec-tour/) of your freshly deployed {{crowdsec.name}} !

## Binary installation

> you of little faith

```
sudo {{wizard.bin}} --bininstall
```

This will deploy a valid/empty {{crowdsec.name}} configuration files and binaries.
Beware, in this state, {{crowdsec.name}} won't monitor/detect anything unless configured.

```
cscli install collection crowdsecurity/linux
```


Installing at least the `crowdsecurity/linux` collection will provide you :

 - syslog parser
 - geoip enrichment
 - date parsers


You will need as well to configure your {{ref.acquis}} file to feed {{crowdsec.name}} some logs.





## From source

!!! warning "Requirements"
    
    * [Go](https://golang.org/doc/install) v1.13+
    * `git clone {{crowdsec.url}}`
    * [jq](https://stedolan.github.io/jq/download/)


Go in {{crowdsec.name}} folder and build the binaries :

```bash
cd crowdsec
```
```bash
make build
```


{{crowdsec.name}} bin will be located in `./cmd/crowdsec/crowdsec` and {{cli.name}} bin in `cmd/crowdsec-cli/{{cli.bin}}` 

Now, you can install either with [interactive wizard](#using-the-interactive-wizard) or the [unattended mode](#using-unattended-mode).


# Upgrading

The wizard itself comes with a `--upgrade` option, that will upgrade existing crowdsec installation to the current version.

The wizard takes care of backuping configurations on your behalf, and puts them into an archive :

 - backup your parsers,scenarios,collections, either from hub or your local ones
 - simulation configuration
 - API credentials
 - acquisition.yaml file
 - plugin(s) configuration

It will then install the new/current crowdsec version, and restore everything that has been backed up!


```bash
$ sudo ./wizard.sh --upgrade
[10/05/2020:11:27:34 AM][INF] crowdsec_wizard: Backing up existing configuration
WARN[0000] Starting configuration backup                
INFO[0000] saving, version:0.1, up-to-date:true          file=crowdsecurity/syslog-logs type=parsers
...
INFO[0000] Wrote 7 entries for parsers to /tmp/tmp.z54P27aaW0/parsers//upstream-parsers.json  file=crowdsecurity/geoip-enrich type=parsers
INFO[0000] Wrote 0 entries for postoverflows to /tmp/tmp.z54P27aaW0/postoverflows//upstream-postoverflows.json  file=crowdsecurity/seo-bots-whitelist type=postoverflows
INFO[0000] Wrote 9 entries for scenarios to /tmp/tmp.z54P27aaW0/scenarios//upstream-scenarios.json  file=crowdsecurity/smb-bf type=scenarios
INFO[0000] Wrote 4 entries for collections to /tmp/tmp.z54P27aaW0/collections//upstream-collections.json  file=crowdsecurity/vsftpd type=collections
INFO[0000] Saved acquis to /tmp/tmp.z54P27aaW0/acquis.yaml 
INFO[0000] Saved default yaml to /tmp/tmp.z54P27aaW0/default.yaml 
INFO[0000] Saved configuration to /tmp/tmp.z54P27aaW0   
INFO[0000] Stop docker metabase /crowdsec-metabase      
[10/05/2020:11:27:36 AM][INF] crowdsec_wizard: Removing crowdsec binaries
[10/05/2020:11:27:36 AM][INF] crowdsec_wizard: crowdsec successfully uninstalled
[10/05/2020:11:27:36 AM][INF] crowdsec_wizard: Installing crowdsec
...
[10/05/2020:11:27:36 AM][INF] crowdsec_wizard: Restoring configuration
...
INFO[0004] Restore acquis to /etc/crowdsec/config/acquis.yaml 
INFO[0004] Restoring  '/tmp/tmp.z54P27aaW0/plugins/backend/database.yaml' to '/etc/crowdsec/plugins/backend/database.yaml' 
[10/05/2020:11:27:41 AM][INF] crowdsec_wizard: Restoring saved database
[10/05/2020:11:27:41 AM][INF] crowdsec_wizard: Finished, restarting

```

As usual, if you experience any issues, let us know :)

# Uninstalling

You can uninstall crowdsec using the wizard : `sudo ./wizard.sh --uninstall`




