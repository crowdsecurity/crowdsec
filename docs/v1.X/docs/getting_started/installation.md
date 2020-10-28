# Installation

Fetch {{v1X.crowdsec.name}}'s latest version [here]({{v1X.crowdsec.download_url}}).

```bash
tar xvzf crowdsec-release.tgz
```
```bash
cd crowdsec-v0.X.X
```

A {{v1X.wizard.name}} is provided to help you deploy {{v1X.crowdsec.name}} and {{v1X.cli.name}}.

## Using the interactive wizard

```
sudo {{v1X.wizard.bin}} -i
```

![crowdsec](../assets/images/crowdsec_install.gif)

The {{v1X.wizard.name}} is going to guide you through the following steps :

 - detect services that are present on your machine
 - detect selected services logs
 - suggest collections (parsers and scenarios) to deploy
 - deploy & configure {{v1X.crowdsec.name}} in order to watch selected logs for selected scenarios
 
The process should take less than a minute, [please report if there are any issues]({{v1X.wizard.bugreport}}).

You are then ready to [take a tour](/Crowdsec/v1/getting_started/crowdsec-tour/) of your freshly deployed {{v1X.crowdsec.name}} !

## Binary installation

> you of little faith

```
sudo {{v1X.wizard.bin}} --bininstall
```

This will deploy a valid/empty {{v1X.crowdsec.name}} configuration files and binaries.
Beware, in this state, {{v1X.crowdsec.name}} won't monitor/detect anything unless configured.

```
cscli install collection crowdsecurity/linux
```


Installing at least the `crowdsecurity/linux` collection will provide you :

 - syslog parser
 - geoip enrichment
 - date parsers


You will need as well to configure your {{v1X.ref.acquis}} file to feed {{v1X.crowdsec.name}} some logs.





## From source

!!! warning "Requirements"
    
    * [Go](https://golang.org/doc/install) v1.13+
    * `git clone {{v1X.crowdsec.url}}`
    * [jq](https://stedolan.github.io/jq/download/)


Go in {{v1X.crowdsec.name}} folder and build the binaries :

```bash
cd crowdsec
```
```bash
make build
```


{{v1X.crowdsec.name}} bin will be located in `./cmd/crowdsec/crowdsec` and {{v1X.cli.name}} bin in `cmd/crowdsec-cli/{{v1X.cli.bin}}` 

Now, you can install either with [interactive wizard](#using-the-interactive-wizard) or the [unattended mode](#using-unattended-mode).