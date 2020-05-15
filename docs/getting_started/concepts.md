{{crowdsec.Name}}'s main goal is to crunch logs to detect things (duh).
You will find below an introduction to the concepts that are frequently used within the documentation.

## Acquisition

[Acquistion configuration](/guide/crowdsec/acquisition/) defines which streams of information {{crowdsec.name}} is going to process.

At the time of writing, it's mostly files, but it should be more or less any kind of stream, such as a kafka topic or a cloudtrail.

Acquisition configuration always contains a stream (ie. a file to tail) and a tag (ie. "these are in syslog format" "these are non-syslog nginx logs").

## Parsers

For logs to be able to be exploited and analyzed, they need to be parsed and normalized, and this is where parsers are used. In most cases, you should be able to find the relevant parsers on our {{hub.htmlname}}.

A parser usually has a specific scope. For example, if you are using [nginx](https://nginx.org), you will probably want to use the `crowdsecurity/nginx-logs` which allows your {{crowdsec.name}} setup to parse nginx's access and error logs.

You can as well [write your own](/write_configurations/parsers/) !

## Enrichers

Enrichment is the action of adding extra context to an event based on the information we already have, so that better decision can later be taken. In most cases, you should be able to find the relevant enrichers on our {{hub.htmlname}}.

The most common/simple type of enrichment would be geoip-enrichment of an event (adding information such as : origin country, origin AS and origin IP range to an event).

Once again, you should be able to find the ones you're looking for on the {{hub.htmlname}} !

## Scenarios

Scenarios is the expression of a heuristic that allows you to qualify a specific event (usually an attack). In most cases, you should be able to find the relevant scenarios on our {{hub.htmlname}}.

While not going [into details](/references/scenarios/), a scenario often evolves around several central things. 

(Let's take "we want to detect ssh bruteforce" as an example!)

 - A filter : to know which events are elligible ("I'm looking for failed authentication")
 - A grouping key : how are we going to "group" events together to give them a meaning ("We are going to group by source IP performing said failed authentication")
 - A rate-limit configuration including burst capacity : to qualify an attack and limit the false positives, we are characterizing the speed at which events need to happen (For a ssh bruteforce, it could be "at least 10 failed authentication within 1 minute")

You can as well [write your own](/write_configurations/scenarios/) !


## Collections

To make user's life easier, "collections" are available, which are just a bundle of parsers and scenarios.
In this way, if you want to cover basic use-cases of let's say "nginx", you can just install the `crowdsecurity/nginx` collection that is composed of `crowdsecurity/nginx-logs` parser, as well as generic http scenarios such as `crowdsecurity/base-http-scenarios`.

As usual, those can be found on the {{hub.htmlname}} !
