<center>[[Hub]]({{hub.url}}) [[Releases]]({{crowdsec.download_url}})</center>

# What is {{crowdsec.Name}} ?

{{crowdsec.Name}} is an open-source and lightweight software that allows you to detect peers with malevolent behaviors and block them from accessing your systems at various level (infrastructural, system, applicative).

To achieve this, {{crowdsec.Name}} reads logs from different sources (files, streams ...) to parse, normalize and enrich them before matching them to threats patterns called scenarios. 

{{crowdsec.Name}} is a modular and plug-able framework, it ships a large variety of well known popular scenarios; users can choose what scenarios they want to be protected from as well as easily adding new custom ones to better fit their environment.

Detected malevolent peers can then be prevented from accessing your resources by deploying [blockers]({{hub.plugins_url}}) at various levels (applicative, system, infrastructural) of your stack.

One of the advantages of Crowdsec when compared to other solutions is its crowded aspect : Meta information about detected attacks (source IP, time and triggered scenario) are sent to a central API and then shared amongst all users.

Besides detecting and stopping attacks in real time based on your logs, it allows you to preemptively block known bad actors from accessing your information system.


## Components

{{crowdsec.name}} ecosystem is based on the following tools :

 - {{crowdsec.name}} is the "service" that runs in the background, processes logs and keeps track of attacks
 - [{{cli.name}}]({{cli.main_doc}}) is the command line interface for humans, it allows you to view, add, or remove bans as well as to install, find ,or update scenarios and parsers
 - [{{plugins.name}}]({{hub.plugins_url}}) are the components that block malevolent traffic, and can be deployed anywhere in your stack

## Architecture

![Architecture](assets/images/crowdsec_architecture.png)

## Moving forward

To learn more about {{crowdsec.name}} and give it a try, please see :

 - [How to install {{crowdsec.name}}](/getting_started/installation/)
 - [Take a quick tour of {{crowdsec.name}} and {{cli.name}} features](/getting_started/crowdsec-tour/)
 - [Deploy {{plugins.name}} to stop malevolent peers](/blockers/)
 - [Observability of {{crowdsec.name}}](/observability/overview/)
 - [Understand {{crowdsec.name}} configuration](/getting_started/concepts/)
 - [FAQ](getting_started/FAQ/)

If you have a functional {{crowdsec.name}} setup, you might want to find the right [{{plugins.name}}](/blockers/).

Don't hesitate to look at the [glossary](/getting_started/glossary/) for clarification !

