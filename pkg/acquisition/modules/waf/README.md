Ongoing poc for Coraza

For config:

coraza_inband.conf:
```
SecRuleEngine On
SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains password" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
```


coraza_outofband.conf:
```
SecRuleEngine On
SecRule ARGS:id "@eq 2" "id:2, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains totolol" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
```


acquis.yaml :

```
listen_addr: 127.0.0.1
listen_port: 4241
path: /
source: waf
labels:
  type: waf
```
