## Understanding parsers


Parsers are configurations that define a transformation on an {{event.htmlname}}.
Parsers are expressed as YAML files composed of one or more individual 'parsing' nodes.
An {{event.htmlname}} can be the representation of a log line, or an overflow.

A parser itself can be used to perform various actions, including :

 - Parse a string with regular expression (grok patterns)
 - Enrich an event by relying on "external" code (such as the geoip-enrichment parser)
 - Process one or more fields of an {{event.name}} with {{expr.htmlname}}


A parser node might look like :
```yaml
#if 'onsuccess' is 'next_stage', the event will make it to next stage if this node succeed
onsuccess: next_stage
#a 'debug' (bool) flag allow to enable node level debug  in any node to enable local debug
debug: true
#a filter to decide if the Event is elligible for this parser node
filter: "evt.Parsed.program == 'kernel'"
#a unique name to allow easy debug & logging
name: crowdsecurity/demo-iptables
#this is for humans
description: "Parse iptables drop logs"
#we can define named capture groups (a-la-grok)
pattern_syntax:
  MYCAP: ".*"
#an actual grok pattern (regular expression with named capture groupe)
grok:
  pattern: ^xxheader %{MYCAP:extracted_value} trailing stuff$
  #we define on which field the regular expression must be applied
  apply_on: evt.Parsed.some_field
#statics are transformations that are applied on the event if the node is considered "successfull"
statics:
  #to which field the value will be written (here -> evt.Meta.log_type)
  - meta: log_type
    #and here a static value
    value: parsed_testlog
  #another one
  - meta: source_ip
    #here the value stored is the result of a dynamic expression
    expression: "evt.Parsed.src_ip"
```


The parser nodes are processed sequentially based on the alphabetical order of {{stages.htmlname}} and subsequent files.
If the node is considered successful (grok is present and returned data or no grok is present) and "onsuccess" equals to `next_stage`, then the {{event.name}} is moved to the next stage.


## Parser trees

A parser node can contain sub-nodes, to provide proper branching.
It can be useful when you want to apply different parsing based on different criterias, or when you have a set of candidates parsers that you want to apply to an event :

```yaml
#This first node will capture/extract some value
filter: "evt.Line.Labels.type == 'type1'"
name: tests/base-grok-root
pattern_syntax:
  MYCAP: ".*"
grok:
  pattern: ^... %{MYCAP:extracted_value} ...$
  apply_on: Line.Raw
statics:
  - meta: state
    value: root-done
  - meta: state_sub
    expression: evt.Parsed.extracted_value
---
#and this node will apply different patterns to it
filter: "evt.Line.Labels.type == 'type1' && evt.Meta.state == 'root-done'"
name: tests/base-grok-leafs
onsuccess: next_stage
#the sub-nodes will process the result of the master node
nodes:
  - filter: "evt.Parsed.extracted_value == 'VALUE1'"
    debug: true
    statics:
      - meta: final_state
        value: leaf1
  - filter: "evt.Parsed.extracted_value == 'VALUE2'"
    debug: true
    statics:
      - meta: final_state
        value: leaf2
```

The logic is that the `tests/base-grok-root` node will be processed first and will alter the event (here mostly by extracting some text from the `Line.Raw` field into `Parsed` thanks to the `grok` pattern and the `statics` directive).

The event will then continue its life and be parsed by the the following `tests/base-grok-leafs` node.
This node has `onsuccess` set to `next_stage` which means that if the node is successful, the event will be moved to the next stage.

This node consists actually of two sub-nodes that have different conditions (branching) to allow differential treatment of said event.

A real-life example can be seen when it comes to parsing HTTP logs.
HTTP ACCESS and ERROR logs often have different formats, and thus our "nginx" parser needs to handle both formats

```yaml
filter: "evt.Parsed.program == 'nginx'"
onsuccess: next_stage
name: crowdsecurity/nginx-logs
nodes:
  - grok:
      #this is the access log
      name: NGINXACCESS
      apply_on: message
      statics:
        - meta: log_type
          value: http_access-log
        - target: evt.StrTime
          expression: evt.Parsed.time_local
  - grok:
        # and this one the error log
        name: NGINXERROR
        apply_on: message
        statics:
          - meta: log_type
            value: http_error-log
          - target: evt.StrTime
            expression: evt.Parsed.time
# these ones apply for both grok patterns
statics:
  - meta: service
    value: http
  - meta: source_ip
    expression: "evt.Parsed.remote_addr"
  - meta: http_status
    expression: "evt.Parsed.status"
  - meta: http_path
    expression: "evt.Parsed.request"
```

## Parser directives

### debug

```yaml
debug: true|false
```
_default: false_

If set to to `true`, enabled node level debugging.
It is meant to help understanding parser node behaviour by providing contextual logging.


### filter

```yaml
filter: expression
```

`filter` must be a valid {{expr.htmlname}} expression that will be evaluated against the {{event.htmlname}}.

If `filter` evaluation returns true or is absent, node will be processed.

If `filter` returns `false` or a non-boolean, node won't be processed.

Here is the [expr documentation](https://github.com/antonmedv/expr/tree/master/docs).

Examples :

 - `filter: "evt.Meta.foo == 'test'"`
 - `filter: "evt.Meta.bar == 'test' && evt.Meta.foo == 'test2'`


### grok

```yaml
grok:
  name: NAMED_EXISTING_PATTERN
  apply_on: source_field
```

```yaml
grok:
  pattern: ^a valid RE2 expression with %{CAPTURE:field}$
  apply_on: source_field
```

The `grok` structure in a node represent a regular expression with capture group (grok pattern) that must be applied on a field of {{event.name}}.

The pattern can : 

 - be imported by name (if present within the core of {{crowdsec.name}})
 - defined in place

In both case, the pattern must be a valid RE2 expression.
The field(s) returned by the regular expression are going to be merged into the `Parsed` associative array of the `Event`.



### name

```yaml
name: explicit_string
```

The *mandatory* name of the node. If not present, node will be skipped at runtime.
It is used for example in debug log to help you track things.

### nodes

```yaml
nodes:
 - filter: ...
   grok: ...
```

`nodes` is a list of parser nodes, allowing you to build trees.
Each subnode must be valid, and if any of the subnodes succeed, the whole node is considered successful. 

### onsuccess

```
onsuccess: next_stage|continue
```

_default: continue_

if set to `next_stage` and the node is considered successful, the {{event.name}} will be moved directly to next stage without processing other nodes in the current stage.

### pattern_syntax

```yaml
pattern_syntax:
  CAPTURE_NAME: VALID_RE2_EXPRESSION
```

`pattern_syntax` allows user to define named capture group expressions for future use in grok patterns.
Regexp must be a valid RE2 expression.

```yaml
pattern_syntax:
  MYCAP: ".*"
grok:
  pattern: ^xxheader %{MYCAP:extracted_value} trailing stuff$
  apply_on: Line.Raw
```


### statics

```yaml
statics:
 - target: evt.Meta.target_field
   value: static_value
 - meta: target_field
   expression: evt.Meta.target_field + ' this_is' + ' a dynamic expression'
 - enriched: target_field
   value: static_value
```

`statics` is a list of directives that will be executed when the node is considered successful.
Each entry of the list is composed of a target (where to write) and a source (what data to write).

**Target**

The target aims at being any part of the {{event.htmlname}} object, and can be expressed in different ways :

    - `meta: <target_field>`
    - `parsed: <target_field>`
    - `enriched: <target_field>`
    - a dynamic target (please note that the **current** event is accessible via the `evt.` variable) :
         - `target: evt.Meta.foobar`
         - `target: Meta.foobar`
         - `target: evt.StrTime`
    
 
 **Source**

 The source itself can be either a static value, or an {{expr.htmlname}} result :

```yaml
statics:
  - meta: target_field
    value: static_value
  - meta: target_field
    expression: evt.Meta.another_field
  - meta: target_field
    expression: evt.Meta.target_field + ' this_is' + ' a dynamic expression'
```


## Parser concepts


### Success and failure

A parser is considered "successful" if :
 - A grok pattern was present and successfully matched
 - No grok pattern was present
 
  
