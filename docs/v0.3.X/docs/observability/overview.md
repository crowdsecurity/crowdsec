# Observability Overview

Observability in security software is crucial, especially when this software might take important decision such as blocking IP addresses.

We attempt to provide good observability of {{v0X.crowdsec.name}}'s behavior :

 - {{v0X.crowdsec.name}} itself exposes a [prometheus instrumentation](/Crowdsec/v0/observability/prometheus/)
 - {{v0X.cli.Name}} allows you to view part of prometheus metrics in [cli (`{{v0X.cli.bin}} metrics`)](/Crowdsec/v0/observability/command_line/)
 - {{v0X.crowdsec.name}} logging is contextualized for easy processing
 - for **humans**, {{v0X.cli.name}} allows you to trivially start a service [exposing dashboards](/Crowdsec/v0/observability/dashboard/) (using [metabase](https://www.metabase.com/))

Furthermore, most of {{v0X.crowdsec.name}} configuration should allow you to enable partial debug (ie. per-scenario, per-parser etc.)

