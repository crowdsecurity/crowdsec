# Observability Overview

Observability in security software is crucial, especially when this software might take important decision such as blocking IP addresses.

We attempt to provide good observability of {{crowdsec.name}}'s behavior :

 - {{crowdsec.name}} itself exposes a [prometheus instrumentation](/observability/prometheus/)
 - {{cli.Name}} allows you to view part of prometheus metrics in [cli (`{{cli.bin}} metrics`)](/observability/command_line/)
 - {{crowdsec.name}} logging is contextualized for easy processing
 - for **humans**, {{cli.name}} allows you to trivially start a service [exposing dashboards](/observability/dashboard/) (using [metabase](https://www.metabase.com/))

Furthermore, most of {{crowdsec.name}} configuration should allow you to enable partial debug (ie. per-scenario, per-parser etc.)

