![gopherbadger-tag-do-not-edit]

# Parser

Parser is in charge of turning raw log lines into objects that can be manipulated by heuristics.
Parsing has several stages represented by directories on config/stage.
The alphabetical order dictates the order in which the stages/parsers are processed.

The runtime representation of a line being parsed (or an overflow) is an `Event`, and has fields that can be manipulated by user :
 - Parsed : a string dict containing parser outputs
 - Meta : a string dict containing meta information about the event
 - Line : a raw line representation
 - Overflow : a representation of the overflow if applicable

The Event structure goes through the stages, being altered with each parsing step.
It's the same object that will be later poured into buckets.

# Parser configuration

A parser configuration is a `Node` object, that can contain grok patterns, enrichement instructions.

For example :

```yaml
filter: "evt.Line.Labels.type == 'testlog'"
debug: true
onsuccess: next_stage
name: tests/base-grok
pattern_syntax:
  MYCAP: ".*"
nodes:
  - grok:
      pattern: ^xxheader %{MYCAP:extracted_value} trailing stuff$
      apply_on: Line.Raw
statics:
  - meta: log_type
    value: parsed_testlog
```

### Name

*optional* if present and prometheus or profiling are activated, stats will be generated for this node.

### Filter

> `filter: "Line.Src endsWith '/foobar'"`

 - *optional* `filter` : an [expression](https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md) that will be evaluated against the runtime of a line (`Event`)
	- if the `filter` is present and returns false, node is not evaluated
	- if `filter` is absent or present and returns true, node is evaluated

### Debug flag

> `debug: true`

 - *optional* `debug` : a bool that sets debug of the node to true (applies at runtime and configuration parsing)

### OnSuccess flag
> `onsuccess: next_stage|continue`

 - *mandatory* indicates the behaviour to follow if node succeeds. `next_stage` make line go to next stage, while `continue` will continue processing of current stage.

### Statics

```yaml
statics:
    - meta: service
      value: tcp
    - meta: source_ip
      expression: "Event['source_ip']"
    - parsed: "new_connection"
      expression: "Event['tcpflags'] contains 'S' ? 'true' : 'false'"
    - target: Parsed.this_is_a_test
      value: foobar
```

Statics apply when a node is considered successful, and are used to alter the `Event` structure.
An empty node, a node with a grok pattern that succeeded or an enrichment directive that worked are successful nodes.
Statics can :
 - meta: add/alter an entry in the `Meta` dict
 - parsed: add/alter an entry in the `Parsed` dict
 - target: indicate a destination field by name, such as Meta.my_key
The source of data can be :
 - value: a static value
 - expr_result : the result of an expression


### Grok patterns

Grok patterns are used to parse one field of `Event` into one or several others :

```yaml
grok:
  name: "TCPDUMP_OUTPUT"
  apply_on: message
```

`name` is the name of a pattern loaded from `patterns/`. 
Base patterns can be seen on the repo : https://github.com/crowdsecurity/grokky/blob/master/base.go


---


```yaml
grok:
  pattern: "^%{GREEDYDATA:request}\\?%{GREEDYDATA:http_args}$"
  apply_on: request
```
`pattern`  which is a valid pattern, optionally with a `apply_on` that indicates to which field it should be applied


### Patterns syntax

Present at the `Event` level, the `pattern_syntax` is a list of subgroks to be declared.

```yaml
pattern_syntax:
  DIR: "^.*/"
  FILE: "[^/].*$"
```


### Enrichment

Enrichment mechanism is exposed via statics :

```yaml
statics:
  - method: GeoIpCity
    expression: Meta.source_ip
  - meta: IsoCode
    expression: Enriched.IsoCode
  - meta: IsInEU
    expression: Enriched.IsInEU
```

The `GeoIpCity` method is called with the value of `Meta.source_ip`.
Enrichment plugins can output one or more key:values in the `Enriched` map, 
and it's up to the user to copy the relevant values to `Meta` or such.

# Trees

The `Node` object allows as well a `nodes` entry, which is a list of `Node` entries, allowing you to build trees.

```yaml
filter: "Event['program'] == 'nginx'" #A
nodes: #A'
  - grok: #B
      name: "NGINXACCESS"
      # this statics will apply only if the above grok pattern matched
      statics: #B'
        - meta: log_type
          value: "http_access-log"
  - grok: #C
      name: "NGINXERROR"
      statics:
        - meta: log_type
          value: "http_error-log"
statics: #D
  - meta: service
    value: http
```

The evaluation process of a node is as follow :
 - apply the `filter` (A), if it doesn't match, exit
 - iterate over the list of nodes (A') and apply the node process to each.
 - if a `grok` entry is present, process it
	- if the `grok` entry returned data, apply the local statics of the node (if the grok 'B' was successful, apply B' statics)
 - if any of the `nodes` or the `grok` was successful, apply the statics (D)

# Code Organisation

Main structs :
 - Node (config.go) : the runtime representation of parser configuration
 - Event (runtime.go) : the runtime representation of the line being parsed

Main funcs :
 - CompileNode : turns YAML into runtime-ready tree (Node)
 - ProcessNode : process the raw line against the parser tree, and produces ready-for-buckets data

