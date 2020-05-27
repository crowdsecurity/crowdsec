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