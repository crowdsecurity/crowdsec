
# Global overview

{{v1X.crowdsec.Name}} runtime revolves around a few simple concepts :

 - It read logs (defined via {{v1X.ref.acquis}} config)
 - Those logs are parsed via {{v1X.ref.parsers}} and eventually enriched
 - Those normalized logs are then matched against the {{v1X.ref.scenarios}} that the user deployed
 - When a scenario is "triggered", {{v1X.crowdsec.Name}} generates an {{v1X.alert.Htmlname}} and eventually one or more associated {{v1X.decision.Htmlname}} :
    - The alert is here mostly for tracability, and will stay even after the decision expires
    - The decision on the other hand, is short lived, and tells *what* action should be taken against the offending ip/range/user...
 - Those information (the signal, the associated decisions) are then sent to crowdsec's {{v1X.lapi.htmlname}} and stored in the database

As you might have guessed by now, {{v1X.crowdsec.Name}} itself does the detection part and stores those decisions.
Then, {{v1X.bouncers.htmlname}} can "consume" those decisions (via the very same {{v1X.lapi.htmlname}}) and apply some actual remediation.

## Crowd sourced aspect

 [[References](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=CAPI)]

Whenever the {{v1X.lapi.htmlname}} receives an alert with associated decisions, the meta information about the alert are shared with our central api :

 - The source ip that triggered the alert
 - The scenario that was triggered
 - The timestamp of the attack

These are the only information that are sent to our API. Those are then processed on our side to be able to redistribute relevant blocklists to all the participants. You can check the central API documentation in the references link to have an exhaustive view of what might be shared between your instance and our services.

## Bouncers

[[References](/Crowdsec/v1/bouncers/)]

Bouncers are standalone software pieces in charge of acting upon IPs that triggered alerts.
To do so, bouncers are going to query the local API to know if there is an existing decisions against a given IP, range, username etc. [You can find a list of existing bouncers on the hub]({{v1X.bouncers.url}})



# Configuration items

## Acquisition

[[References](/Crowdsec/v1/references/acquisition/)]

Acquistion configuration defines which streams of information {{v1X.crowdsec.name}} is going to process.

At the time of writing, it's mostly files or journald, but it should be more or less any kind of stream, such as a kafka topic or a cloudtrail.

Acquisition configuration always contains a stream (ie. a file to tail) and a tag (ie. "these are in syslog format" "these are non-syslog nginx logs").

File acquisition configuration is defined as :

```yaml
filenames:
  - /var/log/auth.log
labels:
  type: syslog
```

The `labels` part is here to tag the incoming logs with a type. `labels.type` are used by the parsers to know which logs to process.

## Stages

[[References](/Crowdsec/v1/references/parsers/#stages)]

Stages concept is central to data parsing in {{v1X.crowdsec.name}}, as it allows to have various "steps" of parsing. All parsers belong to a given stage. While users can add or modify the stages order, the following stages exist :

 - `s00-raw` : low level parser, such as syslog
 - `s01-parse` :  most of the services parsers (ssh, nginx etc.)
 - `s02-enrich` : enrichment that requires parsed events (ie. geoip-enrichment) or generic parsers that apply on parsed logs (ie. second stage http parser)


Every event starts in the first stage, and will move to the next stage once it has been successfully processed by a parser that has the `onsuccess` directive set to `next_stage`, and so on until it reaches the last stage, when it's going to start to be matched against scenarios. Thus a sshd log might follow this pipeline :

 - `s00-raw` : be parsed by `crowdsecurity/syslog-logs` (will move event to the next stage)
 - `s01-raw` : be parsed by `crowdsecurity/sshd-logs` (will move event to the next stage)
 - `s02-enrich` : will be parsed by `crowdsecurity/geoip-enrich` and `crowdsecurity/dateparse-enrich`

## Parsers

[[References](/Crowdsec/v1/references/parsers/)]

For logs to be able to be exploited and analyzed, they need to be parsed and normalized, and this is where parsers are used.

A parser is a YAML configuration file that describes how a string is being parsed. Said string can be a log line, or a field extracted from a previous parser. While a lot of parsers rely on the **GROK** approach (a.k.a regular expression named capture groups), parsers can as well reference enrichment modules to allow specific data processing.

A parser usually has a specific scope. For example, if you are using [nginx](https://nginx.org), you will probably want to use the `crowdsecurity/nginx-logs` which allows your {{v1X.crowdsec.name}} setup to parse nginx's access and error logs.

Parsers are organized into stages to allow pipelines and branching in parsing.

See the [{{v1X.hub.name}}]({{v1X.hub.url}}) to explore parsers, or see below some examples :

 - [apache2 access/error log parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/apache2-logs.yaml)
 - [iptables logs parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/iptables-logs.yaml)
 - [http logs post-processing](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/http-logs.yaml)

You can as well [write your own](/Crowdsec/v1/write_configurations/parsers/) !





## Enrichers

[[References](/Crowdsec/v1/references/enrichers/)]

Enrichment is the action of adding extra context to an event based on the information we already have, so that better decision can later be taken. In most cases, you should be able to find the relevant enrichers on our {{v1X.hub.htmlname}}.

A common/simple type of enrichment would be [geoip-enrich](https://github.com/crowdsecurity/hub/blob/master/parsers/s02-enrich/crowdsecurity/geoip-enrich.yaml) of an event (adding information such as : origin country, origin AS and origin IP range to an event).

Once again, you should be able to find the ones you're looking for on the {{v1X.hub.htmlname}} !

## Scenarios

[[References](/Crowdsec/v1/references/scenarios/)]

Scenarios is the expression of a heuristic that allows you to qualify a specific event (usually an attack).It is a YAML file that describes a set of events characterizing a scenario. Scenarios in {{v1X.crowdsec.name}} gravitate around the [leaky bucket](https://en.wikipedia.org/wiki/Leaky_bucket) principle.

A scenario description includes at least :

 - Event eligibility rules. (For example if we're writing a ssh bruteforce detection we only focus on logs of type `ssh_failed_auth`)
 - Bucket configuration such as the leak speed or its capacity (in our same ssh bruteforce example, we might allow 1 failed auth per 10s and no more than 5 in a short amount of time: `leakspeed: 10s` `capacity: 5`)
 - Aggregation rules : per source ip or per other criterias (in our ssh bruteforce example, we will group per source ip)

The description allows for many other rules to be specified (blackhole, distinct filters etc.), to allow rather complex scenarios.

See the [{{v1X.hub.name}}]({{v1X.hub.url}}) to explore scenarios and their capabilities, or see below some examples :

 - [ssh bruteforce detection](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml)
 - [distinct http-404 scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-scan-uniques_404.yaml)
 - [iptables port scan](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/iptables-scan-multi_ports.yaml)

You can as well [write your own](/Crowdsec/v1/write_configurations/scenarios/) !


## Collections

[[References](/Crowdsec/v1/references/collections/)]

To make user's life easier, "collections" are available, which are just a bundle of parsers and scenarios.
In this way, if you want to cover basic use-cases of let's say "nginx", you can just install the `crowdsecurity/nginx` collection that is composed of `crowdsecurity/nginx-logs` parser, as well as generic http scenarios such as `crowdsecurity/base-http-scenarios`.

As usual, those can be found on the {{v1X.hub.htmlname}} !

## PostOverflows

[[References](/Crowdsec/v1/references/postoverflows)]

A postoverflow is a parser that will be applied on overflows (scenario results) before the decision is written to local DB or pushed to API. Parsers in postoverflows are meant to be used for "expensive" enrichment/parsing process that you do not want to perform on all incoming events, but rather on decision that are about to be taken.

An example could be slack/mattermost enrichment plugin that requires human confirmation before applying the decision or reverse-dns lookup operations.


# Runtime items

## Events

[[References](/Crowdsec/v1/references/events)]

An `Event` is the runtime representation of an item being processed by crowdsec : It be a Log line being parsed, or an Overflow being reprocessed.

The `Event` object is modified by parses, scenarios, and directly via user [statics expressions](/Crowdsec/v1/references/parsers/#statics) (for example).


<!--TBD: check ref-->

## Alerts

[[References](/Crowdsec/v1/references/alerts)]

An `Alert` is the runtime representation of a bucket overflow being processed by crowdsec : It is embedded in an Event.

The `Alert` object is modified by post-overflows and {{v1X.profiles.htmlname}}.

## Decisions

[[References](/Crowdsec/v1/references/decisions)]

A `Decision` is the representation of the consequence of a bucket overflow : a decision against an IP, a range, an AS, a Country, a User, a Session etc.

`Decisions` are generated by Local API (LAPI) when an `Alert` is received, according to the existing {{v1X.profiles.htmlname}}