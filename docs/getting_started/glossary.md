### **Event**

The objects that are processed within {{crowdsec.name}} are named "Events".
An Event can be a log line, or an overflow result. This object layout evolves around a few important items :

 - `Parsed` is an associative array that will be used during parsing to store temporary variables or processing results.
 - `Enriched`, very similar to `Parsed`, is an associative array but is intended to be used for enrichment process.
 - `Overflow` is a `SignalOccurence` structure that represents information about a triggered scenario, when applicable.
 - `Meta` is an associative array that will be used to keep track of meta information about the event. 

_Other fields omitted for clarity, see [`pkg/types/event.go`](https://github.com/crowdsecurity/crowdsec/blob/master/pkg/types/event.go) for detailed definition_

### **Overflow or SignalOccurence**

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



### **Acquisition**

Acquisition and its config (`acquis.yaml`) specify a list of files/ streams to read from (at the time of writing, files are the only input stream supported).

On common setups, {{wizard.name}} interactive installation will take care of it.

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

### **Parser**

A parser is a YAML configuration file that describes how a string is being parsed. Said string can be a log line, or a field extracted from a previous parser. While a lot of parsers rely on the **GROK** approach (a.k.a regular expression named capture groups), parsers can as well reference enrichment modules to allow specific data processing.

Parsers are organized into stages to allow pipelines and branching in parsing.

See the [{{hub.name}}]({{hub.url}}) to explore parsers, or see below some examples :

 - [apache2 access/error log parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/apache2-logs.yaml)
 - [iptables logs parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/iptables-logs.yaml)
 - [http logs post-processing](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/http-logs.yaml)


### **Parser node**

A node is an individual parsing description.
Several nodes might be presented in a single parser file.

### **Node success or failure**

When an {{event.htmlname}} enters a node (because the filter returned true), it can be considered as a success or a failure.
The node will be successful if a grok pattern is present and successfully returned data.
A node is considered to have failed if a grok pattern is present but didn't return data.
If no grok pattern is present, the node will be considered successful.

It ensures that once an event has been parsed, it won't attempt to be processed by other nodes.


### **Stages**

Parsers are organized into "stages" to allow pipelines and branching in parsing.
Each parser belongs to a stage, and can trigger next stage when successful.
At the time of writing, the parsers are organized around 3 stages :

 - `s00-raw` : low level parser, such as syslog
 - `s01-parse` :  most of the services parsers (ssh, nginx etc.)
 - `s02-enrich` : enrichment that requires parsed events (ie. geoip-enrichment) or generic parsers that apply on parsed logs (ie. second stage http parser)

The number and structure of stages can be altered by the user, the directory structure and their alphabetical order dictates in which order stages and parsers are processed.

### **Enricher**

An enricher is a parser that will call external code to process the data instead of processing data based on a regular expression.

See the [geoip-enrich](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/geoip-enrich.yaml) as an example.

### **Scenario**

A scenario is a YAML configuration file that describes a set of events characterizing a scenario.
Scenarios in {{crowdsec.name}} gravitate around the [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket) principle.

A scenario description includes at least :

 - Event eligibility rules. (For example if we're writing a ssh bruteforce detection we only focus on logs of type `ssh_failed_auth`)
 - Bucket configuration such as the leak speed or its capacity (in our same ssh bruteforce example, we might allow 1 failed auth per 10s and no more than 5 in a short amount of time: `leakspeed: 10s` `capacity: 5`)
 - Aggregation rules : per source ip or per other criterias (in our ssh bruteforce example, we will group per source ip)

The description allows for many other rules to be specified (blackhole, distinct filters etc.), to allow rather complex scenarios.

See the [{{hub.name}}]({{hub.url}}) to explore scenarios and their capabilities, or see below some examples :

 - [ssh bruteforce detection](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml)
 - [distinct http-404 scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-scan-uniques_404.yaml)
 - [iptables port scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/iptables-scan-multi_ports.yaml)

### **PostOverflow**

A postoverflow is a parser that will be applied on overflows (scenario results) before the decision is written to local DB or pushed to API. Parsers in postoverflows are meant to be used for "expensive" enrichment/parsing process that you do not want to perform on all incoming events, but rather on decision that are about to be taken.

An example could be slack/mattermost enrichment plugin that requires human confirmation before applying the decision or reverse-dns lookup operations.
