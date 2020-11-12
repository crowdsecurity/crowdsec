<center>[[Hub]]({{v1X.hub.url}}) [[Releases]]({{v1X.crowdsec.download_url}})</center>

# Architecture

![Architecture](assets/images/crowdsec_architecture.png)


## Components

{{v1X.crowdsec.name}} ecosystem is based on the following components :

 - [{{v1X.crowdsec.Name}}]({{v1X.crowdsec.url}}) is the lightweight service that processes logs and keeps track of attacks.
 - [{{v1X.lapi.Name}}]({{v1X.lapi.url}}) is a core component of crowdsec-agent that exposes a local API to interact with crowdsec-agent.
 - [{{v1X.cli.name}}]({{v1X.cli.main_doc}}) is the command line interface for humans, it allows you to view, add, or remove bans as well as to install, find, or update scenarios and parsers
 - [{{v1X.bouncers.name}}]({{v1X.hub.bouncers_url}}) are the components that block malevolent traffic, and can be deployed anywhere in your stack

## Moving forward

To learn more about {{v1X.crowdsec.name}} and give it a try, please see :

 - [How to install {{v1X.crowdsec.name}}](/Crowdsec/v1/getting_started/installation/)
 - [Take a quick tour of {{v1X.crowdsec.name}} and {{v1X.cli.name}} features](/Crowdsec/v1/getting_started/crowdsec-tour/)
 - [Observability of {{v1X.crowdsec.name}}](/Crowdsec/v1/observability/overview/)
 - [Understand {{v1X.crowdsec.name}} configuration](/Crowdsec/v1/getting_started/concepts/)
 - [Deploy {{v1X.bouncers.name}} to stop malevolent peers](/Crowdsec/v1/bouncers/)
 - [FAQ](/faq/)

Don't hesitate to reach out if you're facing issues :

 - [report a bug](https://github.com/crowdsecurity/crowdsec/issues/new?assignees=&labels=bug&template=bug_report.md&title=Bug%2F)
 - [suggest an improvement](https://github.com/crowdsecurity/crowdsec/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=Improvment%2F)
 - [ask for help on the forums](https://discourse.crowdsec.net)