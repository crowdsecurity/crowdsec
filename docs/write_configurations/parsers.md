# Writing {{crowdsec.Name}} parser

!!! info
    Please ensure that you have working env or setup test environment before writing your parser.

> In the current example, we'll write a parser for the logs produced by `iptables` (netfilter) with the `-j LOG` target.
> This document aims at detailing the process of writing and testing new parsers.

## Base parser file

The most simple parser can be defined as :

```yaml
filter: 1 == 1
debug: true
onsuccess: next_stage
name: me/myparser
description: a cool parser for my service
grok:
#our grok pattern : capture .*
  pattern: ^%{DATA:some_data}$
#the field to which we apply the grok pattern : the log message itself
  apply_on: message
statics:
  - parsed: is_my_service
    value: yes
```

 - a {{filter.htmlname}} : if the expression is `true`, the event will enter the parser, otherwise, it won't
 - a {{onsuccess.htmlname}} : defines what happens when the {{event.htmlname}} was successfully parsed : shall we continue ? shall we move to next stage ? etc.
 - a name & a description
 - some {{statics.htmlname}} that will modify the {{event.htmlname}}
 - a `debug` flag that allows to enable local debugging information.


We are going to use to following sample log as an example :
```bash
May 11 16:23:43 sd-126005 kernel: [47615895.771900] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=99.99.99.99 DST=127.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=245 ID=51006 PROTO=TCP SPT=45225 DPT=8888 WINDOW=1024 RES=0x00 SYN URGP=0 
May 11 16:23:50 sd-126005 kernel: [47615902.763137] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=44.44.44.44 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=17451 DF PROTO=TCP SPT=53668 DPT=80 WINDOW=14600 RES=0x00 SYN URGP=0 
```

## Let's try our mock parser

!!! warning
    Your yaml file must be in the `config/parsers/s01-parser/` directory (relative to your current test directory).

    For example it can be `~/crowdsec-v0.0.19/tests/config/parsers/s01-parser/myparser.yaml`

    The stage directory might not exist, don't forget to create it.


Setting up our new parser :
```bash
cd crowdsec-v0.X.Y/tests
```

```bash
mkdir -p config/parsers/s01-parser
```
```bash
cp myparser.yaml config/parsers/s01-parser/                  
```

Testing our new parser :
```bash
./crowdsec -c ./dev.yaml -file ./x.log -type foobar
```
<details>
  <summary>Expected output</summary>

```bash
INFO[0000] setting loglevel to info                     
INFO[11-05-2020 15:48:28] Crowdsec v0.0.18-6b1281ba76819fed4b89247a5a673c592a3a9f88
...
DEBU[0000] Event entering node                           id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] eval(TRUE) '1 == 1'                           id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] no ip in event, cidr/ip whitelists not checked  id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] + Grok '' returned 1 entries to merge in Parsed  id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] 	.Parsed['some_data'] = 'May 11 16:23:41 sd-126005 kernel: [47615893.721616] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=99.99.99.99 DST=127.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=245 ID=54555 PROTO=TCP SPT=45225 DPT=8080 WINDOW=1024 RES=0x00 SYN URGP=0 '  id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] + Processing 1 statics                        id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] .Parsed[is_my_service] = 'yes'                id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] Event leaving node : ok                       id=dark-water name=me/myparser stage=s01-parser
DEBU[0000] move Event from stage s01-parser to s02-enrich  id=dark-water name=me/myparser stage=s01-parser
...
```
</details>


We can see our "mock" parser is working, let's see what happened :

 - The event enter the node
 - The `filter` returned true (`1 == 1`) so the {{event.htmlname}} will be processed
 - Our grok pattern (just a `.*` capture) "worked" and captured data (the whole line actually)
 - The grok captures (under the name "some_data") are merged into the `.Parsed` map of the {{event.htmlname}}
 - The {{statics.htmlname}} section is processed, and `.Parsed[is_my_service]` is set to `yes`
 - The {{event.htmlname}} leaves the parser successfully, and because "next_stage" is set, we move the event to the next "stage"

## Writing the GROK pattern

We are going to write a parser for `iptables` logs, they look like this :

```
May 11 16:23:43 sd-126005 kernel: [47615895.771900] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=99.99.99.99 DST=127.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=245 ID=51006 PROTO=TCP SPT=45225 DPT=8888 WINDOW=1024 RES=0x00 SYN URGP=0 
May 11 16:23:50 sd-126005 kernel: [47615902.763137] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=44.44.44.44 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=17451 DF PROTO=TCP SPT=53668 DPT=80 WINDOW=14600 RES=0x00 SYN URGP=0 

```

Using an [online grok debugger](https://grokdebug.herokuapp.com/) or an [online regex debugger](https://www.debuggex.com/), we come up with the following grok pattern :

`\[%{DATA}\]+.*(%{WORD:action})? IN=%{WORD:int_eth} OUT= MAC=%{IP}:%{MAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip} LEN=%{INT:length}.*PROTO=%{WORD:proto} SPT=%{INT:src_port} DPT=%{INT:dst_port}.*`

!!! warning
    Check if the pattern you are looking for is not already present in [patterns configuration](https://github.com/crowdsecurity/crowdsec/tree/master/config/patterns).


## Test our new pattern

Now, let's integrate our GROK pattern within our YAML :

```yaml
#let's set onsuccess to "next_stage" : if the log is parsed, we can consider it has been dealt with
onsuccess: next_stage
#debug, for reasons (don't do this in production)
debug: true
#as seen in our sample log, those logs are processed by the system and have a progname set to 'kernel'
filter: "1 == 1"
#name and description:
name: crowdsecurity/iptables-logs
description: "Parse iptables drop logs"
grok:
#our grok pattern
  pattern: \[%{DATA}\]+.*(%{WORD:action})? IN=%{WORD:int_eth} OUT= MAC=%{IP}:%{MAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip} LEN=%{INT:length}.*PROTO=%{WORD:proto} SPT=%{INT:src_port} DPT=%{INT:dst_port}.*
#the field to which we apply the grok pattern : the log message itself
  apply_on: message
statics:
  - parsed: is_my_service
    value: yes
```


```bash
./crowdsec -c ./dev.yaml -file ./x.log -type foobar
```


<details>
  <summary>Expected output</summary>

```bash
INFO[0000] setting loglevel to info                     
INFO[11-05-2020 16:18:58] Crowdsec v0.0.18-6b1281ba76819fed4b89247a5a673c592a3a9f88 
...
DEBU[0000] Event entering node                           id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] eval(TRUE) '1 == 1'                           id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] no ip in event, cidr/ip whitelists not checked  id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] + Grok '' returned 8 entries to merge in Parsed  id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['dst_port'] = '8080'                 id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['action'] = ''                       id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['int_eth'] = 'enp1s0'                id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['src_ip'] = '99.99.99.99'         id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['dst_ip'] = '127.0.0.1'           id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['length'] = '40'                     id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['proto'] = 'TCP'                     id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['src_port'] = '45225'                id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] + Processing 1 statics                        id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] .Parsed[is_my_service] = 'yes'                id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] Event leaving node : ok                       id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] move Event from stage s01-parser to s02-enrich  id=lingering-breeze name=crowdsecurity/iptables-logs stage=s01-parser
...
```

</details>

What changed ? We can now see that the fragment captured by the GROK pattern are merged in the `Parsed` array !
We now have parsed data, only a few more changes and we will be done :)

## Finalizing our parser

```yaml
#let's set onsuccess to "next_stage" : if the log is parsed, we can consider it has been dealt with
onsuccess: next_stage
#debug, for reasons (don't do this in production)
debug: true
#as seen in our sample log, those logs are processed by the system and have a progname set to 'kernel'
filter: "evt.Parsed.program == 'kernel'"
#name and description:
name: crowdsecurity/iptables-logs
description: "Parse iptables drop logs"
grok:
#our grok pattern
  pattern: \[%{DATA}\]+.*(%{WORD:action})? IN=%{WORD:int_eth} OUT= MAC=%{IP}:%{MAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip} LEN=%{INT:length}.*PROTO=%{WORD:proto} SPT=%{INT:src_port} DPT=%{INT:dst_port}.*
#the field to which we apply the grok pattern : the log message itself
  apply_on: message
statics:
    - meta: log_type
      value: iptables_drop
    - meta: service
      expression: "evt.Parsed.proto == 'TCP' ? 'tcp' : 'unknown'"
    - meta: source_ip
      expression: "evt.Parsed.src_ip"
```

### filter

We changed the {{filter.htmlname}} to correctly filter on the program name.
In the current example, our logs are produced by the kernel (netfilter), and thus the program is `kernel` :

```bash
tail -f /var/log/kern.log
May 11 16:23:50 sd-126005 kernel: [47615902.763137] IN=enp1s0 OUT= MAC=00:08:a2:0c:1f:12:00:c8:8b:e2:d6:87:08:00 SRC=44.44.44.44 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=17451 DF PROTO=TCP SPT=53668 DPT=80 WINDOW=14600 RES=0x00 SYN URGP=0 
```

### statics

We are setting various entries to static or dynamic values to give "context" to the log :

  - `.Meta.log_type` is set to `iptables_drop` (so that we later can filter events coming from this)
  - `.Meta.source_ip` is set the the source ip captured  `.Parsed.src_ip`
  - `.Meta.service` is set the the result of an expression that relies on the GROK output (`proto` field)
  
Look into dedicated {{statics.htmlname}} documentation to know more about its possibilities.


### Testing our finalized parser


```bash
./crowdsec -c ./dev.yaml -file ./x.log -type kernel
```

<details>
  <summary>Expected output</summary>
```bash
...
DEBU[0000] Event entering node                           id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] eval(TRUE) 'evt.Parsed.program == 'kernel''   id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] no ip in event, cidr/ip whitelists not checked  id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] + Grok '' returned 8 entries to merge in Parsed  id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['src_port'] = '45225'                id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['dst_port'] = '8118'                 id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['action'] = ''                       id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['int_eth'] = 'enp1s0'                id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['src_ip'] = '44.44.44.44'            id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['dst_ip'] = '127.0.0.1'              id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['length'] = '40'                     id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] 	.Parsed['proto'] = 'TCP'                     id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] + Processing 3 statics                        id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] .Meta[log_type] = 'iptables_drop'             id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] .Meta[service] = 'tcp'                        id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] .Meta[source_ip] = '44.44.44.44'              id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] Event leaving node : ok                       id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
DEBU[0000] move Event from stage s01-parser to s02-enrich  id=shy-forest name=crowdsecurity/iptables-logs stage=s01-parser
...
```
</details>

## Closing word

We have now a fully functional parser for {{crowdsec.name}} !
We can either deploy it to our production systems to do stuff, or even better, contribute to the {{hub.htmlname}} !








<!-- 





The first field that you will write is the `onsuccess` one. This one indicate what to do in case of success log parsing. Put the value `next_stage` if you want the log to be processed by the next stages in case of parsing success:
```yaml
onsuccess: next_stage
```

Then come the `filter` part. 
You will mostly want to filter on the `program` of the event:

```yaml
filter: evt.Parsed.program == '<program>'
```

The `name` (please name your parser like `<github_account_name>/<parser_name>`):

```yaml
name: crowdsecurity/example
```

A small description: 

```yaml
description: this parser can process X/Y/Z logs from <program>
```


The grok part:

 - If you have only one type of log then you can start with the `grok` object which is defined as below:
```yaml
grok:
  pattern: <your_grok_pattern_here> # can't be used with 'name'
  name: <grok_name> # grok name loaded from https://github.com/crowdsecurity/crowdsec/tree/master/config/patterns. can't be used with 'pattern'
  apply_on: message
  statics:
    - <meta|target> : <field_name>
      <value|expression> : <field_value>
    - <meta|target> : <field_name>
      <value|expression> : <field_value>

```
The grok pattern will be applied on the `message` field of the previous success stage.
The `pattern` and `name` keyword can't be use together


 - If you have more type of logs, you will have to start with the `node` keyword that is a list of grok:

```yaml
nodes:
  grok:
    pattern: <your_first_grok_pattern>
    apply_on: message
    statics:
      - <meta|target> : <field_name>
        <value|expression> : <field_value>
      - <meta|target> : <field_name>
        <value|expression> : <field_value>
  grok:
    pattern: <your_second_grok_pattern>
    apply_on: message
    statics:
      - <meta|target> : <field_name>
        <value|expression> : <field_value>
      - <meta|target> : <field_name>
        <value|expression> : <field_value>
statics:
  - <meta|target> : <field_name>
    <value|expression> : <field_value>
  - <meta|target> : <field_name>
    <value|expression> : <field_value>
```

The `statics` is a process that will set up a value for a given key in the parsed event.
For the field `name` the keyword can be either `meta` or `target`:

 - `meta` : the new field will be created in the evt.Meta object to be accessible like : `evt.Meta.<new_field>`;
```yaml
meta: log_type
```
 - `target`: the name of the new field:
```yaml
target: evt.source_ip
```

For the field value, it can be either `value` or `expression`:

- `value` is the value assigned, for example : `http_access_log`

```yaml
value: http_access_log
```

 - `expression` the result of a parsed field, for example : `evt.Parsed.remote_addr` 
```yaml
expression : evt.Parsed.remote_addr
```

The `statics` can be applied only for the grok it succeed, if it is in the `grok` object, else for whatever grok if at the root level.

Full example with NGINX:

<details>
<summary>Nginx </summary>

```yaml
filter: "evt.Parsed.program == 'nginx'"
onsuccess: next_stage
#debug: true
name: crowdsecurity/nginx-logs
description: "Parse nginx access and error logs"
nodes:
  - grok:
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
</details> -->