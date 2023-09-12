Ongoing poc for Coraza WAAP

# Configuration pieces

## Acquisition

acquisition example:

> `config/acquis.yaml` :

```yaml
listen_addr: 127.0.0.1
listen_port: 4241
path: /
source: waf
labels:
  type: waf
#routines: 1
waap_config: mytest
```

## Waap config

The waap config defines what rules that will be loaded by a given waap engine (associated with an acquis).

> `config/waap_configs/mytest.yaml`

```yaml
name: mytest.yaml
outofband_rules:
 - crowdsec/crs-default
inband_rules:
 - crowdsec/vpatch-default
default_remediation: block
variables_tracking:
 - session_*
# onload:
#  - apply:
#     - DisabledInBandRuleByID(1003)
# pre_eval:
#   - filter: evt.SourceIP == '1.3.4.5' 
#     apply:
#       - DisableOutOfBandRuleByID(2302)
```

# Waap Rules

For the above two to work, we need to have the two refered waap collection installed : `crowdsec/crs-default` and `crowdsec/vpatch-default`. You need to set hub_branch to ...

```yaml
cscli waf-rules install ...
```