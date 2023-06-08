Ongoing poc for Coraza

For config:

coraza_inband.conf:
```shell
SecRuleEngine On
SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains password" "id:2, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
```


coraza_outofband.conf:
```shell
SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:3,phase:1,log,msg:'Invalid id',log,auditlog"
SecRule ARGS:idd "@eq 2" "id:4,phase:1,log,msg:'Invalid id',log,auditlog"
SecRequestBodyAccess On
#We know that because we are not cloning the body in waf.go, the outofband rules cannot access body as it has been consumed.
#We are finding a way around this
#SecRule REQUEST_BODY "@contains totolol" "id:4, phase:2,deny,msg:'Invalid request body',log,auditlog"
#SecRule REQUEST_BODY "@contains password" "id:2, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"

```


acquis.yaml :

```yaml
listen_addr: 127.0.0.1
listen_port: 4241
path: /
source: waf
labels:
  type: waf
```

Coraza parser:

```yaml
onsuccess: next_stage
debug: true
filter: "evt.Parsed.program == 'waf'"
name: crowdsecurity/waf-logs
description: "Parse WAF logs"
statics:
  - parsed: cloudtrail_parsed
    expression: UnmarshalJSON(evt.Line.Raw, evt.Unmarshaled, 'waf')
  - meta: req_uuid
    expression: evt.Unmarshaled.waf.req_uuid
  - meta: source_ip
    expression: evt.Unmarshaled.waf.source_ip
  - meta: rule_id
    expression: evt.Unmarshaled.waf.rule_id
  - meta: action
    expression: evt.Unmarshaled.waf.rule_action
  - meta: service
    value: waf
  - parsed: event_type
    value: waf_match

```

Coraza trigger scenario:

```yaml
type: trigger
filter: evt.Parsed.event_type == "waf_match" && evt.Unmarshaled.waf.rule_type == "inband"
debug: true
name: coroza-triggger
description: here we go
blackhole: 2m
labels:
  type: exploit
  remediation: true
groupby: "evt.Meta.source_ip"
```

Coraza leaky scenario:

```yaml
type: leaky
filter: evt.Parsed.event_type == "waf_match" && evt.Unmarshaled.waf.rule_type == "outofband"
debug: true
name: coroza-leaky
description: here we go
blackhole: 2m
leakspeed: 30s
capacity: 1
labels:
  type: exploit
  remediation: true
groupby: "evt.Meta.source_ip"
distinct: evt.Meta.rule_id
```



To be solved:
 - We need to solve the body cloning issue
 - Merge w/ hub


