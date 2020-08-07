{{crowdsec.Name}}'s main goal is to crunch logs to detect things (duh).
You will find below an introduction to the concepts that are frequently used within the documentation.

## Acquisition

[Acquistion configuration](/guide/crowdsec/acquisition/) defines which streams of information {{crowdsec.name}} is going to process.

At the time of writing, it's mostly files, but it should be more or less any kind of stream, such as a kafka topic or a cloudtrail.

Acquisition configuration always contains a stream (ie. a file to tail) and a tag (ie. "these are in syslog format" "these are non-syslog nginx logs").

File acquisition configuration is defined as :

```yaml
filenames: #a list of file or regexp to read from (supports regular expressions)
  - /var/log/nginx/http_access.log
  - /var/log/nginx/https_access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
---
filenames:
  - /var/log/auth.log
labels:
  type: syslog
```

The `labels` part is here to tag the incoming logs with a type. `labels.type` are used by the parsers to know which logs to process.

## Parsers [[reference](/references/parsers/)]

For logs to be able to be exploited and analyzed, they need to be parsed and normalized, and this is where parsers are used.

A parser is a YAML configuration file that describes how a string is being parsed. Said string can be a log line, or a field extracted from a previous parser. While a lot of parsers rely on the **GROK** approach (a.k.a regular expression named capture groups), parsers can as well reference enrichment modules to allow specific data processing.

A parser usually has a specific scope. For example, if you are using [nginx](https://nginx.org), you will probably want to use the `crowdsecurity/nginx-logs` which allows your {{crowdsec.name}} setup to parse nginx's access and error logs.

Parsers are organized into stages to allow pipelines and branching in parsing.

See the [{{hub.name}}]({{hub.url}}) to explore parsers, or see below some examples :

 - [apache2 access/error log parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/apache2-logs.yaml)
 - [iptables logs parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/iptables-logs.yaml)
 - [http logs post-processing](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/http-logs.yaml)

You can as well [write your own](/write_configurations/parsers/) !


## Stages

Parsers are organized into "stages" to allow pipelines and branching in parsing. Each parser belongs to a stage, and can trigger next stage when successful. At the time of writing, the parsers are organized around 3 stages :

 - `s00-raw` : low level parser, such as syslog
 - `s01-parse` : most of the services parsers (ssh, nginx etc.)
 - `s02-enrich` : enrichment that requires parsed events (ie. geoip-enrichment) or generic parsers that apply on parsed logs (ie. second stage http parser)
 
The number and structure of stages can be altered by the user, the directory structure and their alphabetical order dictates in which order stages and parsers are processed.

Every event starts in the first stage, and will move to the next stage once it has been successfully processed by a parser that has the `onsuccess` directive set to `next_stage`, and so on until it reaches the last stage, when it's going to start to be matched against scenarios. Thus a sshd log might follow this pipeline :

 - `s00-raw` : be parsed by `crowdsecurity/syslog-logs` (will move event to the next stage)
 - `s01-raw` : be parsed by `crowdsecurity/sshd-logs` (will move event to the next stage)
 - `s02-enrich` : will be parsed by `crowdsecurity/geoip-enrich` and `crowdsecurity/dateparse-enrich`



## Enrichers

Enrichment is the action of adding extra context to an event based on the information we already have, so that better decision can later be taken. In most cases, you should be able to find the relevant enrichers on our {{hub.htmlname}}.

A common/simple type of enrichment would be [geoip-enrich](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/geoip-enrich.yaml) of an event (adding information such as : origin country, origin AS and origin IP range to an event).

Once again, you should be able to find the ones you're looking for on the {{hub.htmlname}} !

## Scenarios [[reference](/references/scenarios/)]

Scenarios is the expression of a heuristic that allows you to qualify a specific event (usually an attack).It is a YAML file that describes a set of events characterizing a scenario. Scenarios in {{crowdsec.name}} gravitate around the [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket) principle.

A scenario description includes at least :

 - Event eligibility rules. (For example if we're writing a ssh bruteforce detection we only focus on logs of type `ssh_failed_auth`)
 - Bucket configuration such as the leak speed or its capacity (in our same ssh bruteforce example, we might allow 1 failed auth per 10s and no more than 5 in a short amount of time: `leakspeed: 10s` `capacity: 5`)
 - Aggregation rules : per source ip or per other criterias (in our ssh bruteforce example, we will group per source ip)

The description allows for many other rules to be specified (blackhole, distinct filters etc.), to allow rather complex scenarios.

See the [{{hub.name}}]({{hub.url}}) to explore scenarios and their capabilities, or see below some examples :

 - [ssh bruteforce detection](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml)
 - [distinct http-404 scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-scan-uniques_404.yaml)
 - [iptables port scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/iptables-scan-multi_ports.yaml)

You can as well [write your own](/write_configurations/scenarios/) !


## Collections

To make user's life easier, "collections" are available, which are just a bundle of parsers and scenarios.
In this way, if you want to cover basic use-cases of let's say "nginx", you can just install the `crowdsecurity/nginx` collection that is composed of `crowdsecurity/nginx-logs` parser, as well as generic http scenarios such as `crowdsecurity/base-http-scenarios`.

As usual, those can be found on the {{hub.htmlname}} !

## Event

The objects that are processed within {{crowdsec.name}} are named "Events".
An Event can be a log line, or an overflow result. This object layout evolves around a few important items :

 - `Parsed` is an associative array that will be used during parsing to store temporary variables or processing results.
 - `Enriched`, very similar to `Parsed`, is an associative array but is intended to be used for enrichment process.
 - `Overflow` is a `SignalOccurence` structure that represents information about a triggered scenario, when applicable.
 - `Meta` is an associative array that will be used to keep track of meta information about the event. 

_Other fields omitted for clarity, see [`pkg/types/event.go`](https://github.com/crowdsecurity/crowdsec/blob/master/pkg/types/event.go) for detailed definition_

## Overflow or SignalOccurence

This object holds the relevant information about a scenario that happened : who / when / where / what etc.
Its most relevant fields are :

 - `Scenario` : name of the scenario
 - `Alert_message` : a humanly readable message about what happened
 - `Events_count` : the number of individual events that lead to said overflow
 - `Start_at` + `Stop_at` : timestamp of the first and last events that triggered the scenario
 - `Source` : a binary representation of the source of the attack
 - `Source_[ip,range,AutonomousSystemNumber,AutonomousSystemOrganization,Country]` : string representation of source information
 - `Labels` : an associative array representing the scenario "labels" (see scenario definition)

_Other fields omitted for clarity, see [`pkg/types/signal_occurence.go`](https://github.com/crowdsecurity/crowdsec/blob/master/pkg/types/signal_occurence.go) for detailed definition_

### PostOverflow

A postoverflow is a parser that will be applied on overflows (scenario results) before the decision is written to local DB or pushed to API. Parsers in postoverflows are meant to be used for "expensive" enrichment/parsing process that you do not want to perform on all incoming events, but rather on decision that are about to be taken.

An example could be slack/mattermost enrichment plugin that requires human confirmation before applying the decision or reverse-dns lookup operations.
