# Stages

Parsers are organized into "stages" (named using a "sXX-<stage_name>" convention) to allow pipelines and branching in parsing. Each parser belongs to a stage, and can trigger next stage when successful. At the time of writing, the parsers are organized around 3 stages :

 - `s00-raw` : low level parser, such as syslog
 - `s01-parse` : most of the services parsers (ssh, nginx etc.)
 - `s02-enrich` : enrichment that requires parsed events (ie. geoip-enrichment) or generic parsers that apply on parsed logs (ie. second stage http parser)
 
The number and structure of stages can be altered by the user, the directory structure and their alphabetical order dictates in which order stages and parsers are processed.

Every event starts in the first stage, and will move to the next stage once it has been successfully processed by a parser that has the `onsuccess` directive set to `next_stage`, and so on until it reaches the last stage, when it's going to start to be matched against scenarios. 

## Default stages

- The preliminary stage (`s00-raw`) is mostly the one that will parse the structure of the log. This is where [syslog-logs](https://hub.crowdsec.net/author/crowdsecurity/configurations/syslog-logs) are parsed for example. Such a parser will parse the syslog header to detect the program source.
 
- The main stage (`s01-parse`) is the one that will parse actual applications logs and output parsed data and static assigned values. There is one parser for each type of software. To parse the logs, regexp or GROK pattern are used. If the parser is configured to go to the [`next_stage`](/Crowdsec/v1/references/parsers/#onsuccess), then it will be process by the `enrichment` stage.

- The enrichment (`s02-enrich`) stage is the one that will enrich the normalized log (we call it an event now that it is normalized) in order to get more information for the heuristic process. This stage can be composed of grok patterns and so on, but as well of plugins that can be writen by the community (geiop enrichment, rdns ...) for example [geoip-enrich](https://hub.crowdsec.net/author/crowdsecurity/configurations/geoip-enrich).


## Custom stage

It is possible to write custom stage. If you want some specific parsing or enrichment to be done after the `s02-enrich` stage, it is possible by creating a new folder `s03-<custom_stage>` (and so on). The configuration that will be created in this folder will process the logs configured to go to `next_stage` in the `s02-enrich` stage. 