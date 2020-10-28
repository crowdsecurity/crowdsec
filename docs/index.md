<center>[[Hub]]({{v0X.hub.url}}) [[Releases]]({{v0X.crowdsec.download_url}})</center>


!!! warning
        For crowdsec versions `<= 1.0` please refer to [v0.3.X](/Crowdsec/v0/)

        For crowdsec versions `>= 1.0` please refer to [v1.X](/Crowdsec/v1/)

# What is {{v0X.crowdsec.Name}} ?

[{{v0X.crowdsec.Name}}]({{v0X.crowdsec.url}}) is an open-source and lightweight software that allows you to detect peers with malevolent behaviors and block them from accessing your systems at various level (infrastructural, system, applicative).

To achieve this, {{v0X.crowdsec.Name}} reads logs from different sources (files, streams ...) to parse, normalize and enrich them before matching them to threats patterns called scenarios. 

{{v0X.crowdsec.Name}} is a modular and plug-able framework, it ships a large variety of [well known popular scenarios](https://hub.crowdsec.net/browse/#configurations); users can choose what scenarios they want to be protected from as well as easily adding new custom ones to better fit their environment.

Detected malevolent peers can then be prevented from accessing your resources by deploying [blockers]({{v0X.hub.plugins_url}}) at various levels (applicative, system, infrastructural) of your stack.

One of the advantages of Crowdsec when compared to other solutions is its crowd-sourced aspect : Meta information about detected attacks (source IP, time and triggered scenario) are sent to a central API and then shared amongst all users.

Thanks to this, besides detecting and stopping attacks in real time based on your logs, it allows you to preemptively block known bad actors from accessing your information system.

## Components

{{v0X.crowdsec.name}} ecosystem is based on the following components :

 - [{{v0X.crowdsec.Name}}]({{v0X.crowdsec.url}}) is the lightweight service that processes logs and keeps track of attacks.
 - [{{v0X.cli.name}}]({{v0X.cli.main_doc}}) is the command line interface for humans, it allows you to view, add, or remove bans as well as to install, find, or update scenarios and parsers
 - [{{v0X.blockers.name}}]({{v0X.hub.plugins_url}}) are the components that block malevolent traffic, and can be deployed anywhere in your stack

## Architecture

![Architecture](assets/images/crowdsec_architecture.png)


## Core concepts

{{v0X.crowdsec.name}} relies on {{v0X.parsers.htmlname}} to normalize and enrich logs, and {{v0X.scenarios.htmlname}} to detect attacks, often bundled together in {{v0X.collections.htmlname}} to form a coherent configuration set. For example the collection [`crowdsecurity/nginx`](https://hub.crowdsec.net/author/crowdsecurity/collections/nginx) contains all the necessary parsers and scenarios to deal with nginx logs and the common attacks that can be seen on http servers.

All of those are represented as YAML files, that can be found, shared and kept up-to-date thanks to the {{v0X.hub.htmlname}}, or [easily hand-crafted](/Crowdsec/v0/write_configurations/scenarios/) to address specific needs.


## Main features

{{v0X.crowdsec.Name}}, besides the core "detect and react" mechanism,  is committed to a few other key points :

 - **Easy Installation** : The provided wizard allows a [trivial deployment](/Crowdsec/v0/getting_started/installation/#using-the-interactive-wizard) on most standard setups
 - **Easy daily operations** : Using [cscli](/Crowdsec/v0/cscli/cscli_upgrade/) and the {{v0X.hub.htmlname}}, keeping your detection mechanisms up-to-date is trivial
 - **Observability** : Providing strongs insights on what is going on and what {{v0X.crowdsec.name}} is doing :
    - Humans have [access to a trivially deployable web interface](/Crowdsec/v0/observability/dashboard/)
    - OPs have [access to detailed prometheus metrics](/Crowdsec/v0/observability/prometheus/)
    - Admins have [a friendly command-line interface tool](/Crowdsec/v0/observability/command_line/) 

## Moving forward

To learn more about {{v0X.crowdsec.name}} and give it a try, please see :

 - [How to install {{v0X.crowdsec.name}}](/Crowdsec/v0/getting_started/installation/)
 - [Take a quick tour of {{v0X.crowdsec.name}} and {{v0X.cli.name}} features](/Crowdsec/v0/getting_started/crowdsec-tour/)
 - [Observability of {{v0X.crowdsec.name}}](/Crowdsec/v0/observability/overview/)
 - [Understand {{v0X.crowdsec.name}} configuration](/Crowdsec/v0/getting_started/concepts/)
 - [Deploy {{v0X.blockers.name}} to stop malevolent peers](/Crowdsec/v0/blockers/)
 - [FAQ](getting_started/FAQ/)

Don't hesitate to reach out if you're facing issues :

 - [report a bug](https://github.com/crowdsecurity/crowdsec/issues/new?assignees=&labels=bug&template=bug_report.md&title=Bug%2F)
 - [suggest an improvement](https://github.com/crowdsecurity/crowdsec/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=Improvment%2F)
 - [ask for help on the forums](https://discourse.crowdsec.net)

