# Observability Overview

Observability in security software is crucial, especially when this software might take important decision such as blocking IP addresses.

We attempt to provide good observability of {{v1X.crowdsec.name}}'s behavior :

 - {{v1X.crowdsec.name}} itself exposes a [prometheus instrumentation](/Crowdsec/v1/observability/prometheus/)
 - {{v1X.cli.Name}} allows you to view part of prometheus metrics in [cli (`{{v1X.cli.bin}} metrics`)](/Crowdsec/v1/observability/command_line/)
 - {{v1X.crowdsec.name}} logging is contextualized for easy processing
 - for **humans**, {{v1X.cli.name}} allows you to trivially start a service [exposing dashboards](/Crowdsec/v1/observability/dashboard/) (using [metabase](https://www.metabase.com/))

Furthermore, most of {{v1X.crowdsec.name}} configuration should allow you to enable partial debug (ie. per-scenario, per-parser etc.)

