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
waap_config_path: config/waap-configs/mytest.yaml
```

## Waap config

The waap config defines what rules that will be loaded by a given waap engine (associated with an acquis).

> `config/waap-configs/mytest.yaml`

```yaml
name: default
outofband_rules:
# - crowdsecurity/crs-waf
inband_rules:
# - crowdsecurity/crs-waf
 - crowdsecurity/custom-waf-rule
default_remediation: ban
#on_load:
# - apply:
#     - SetInBand()
pre_eval:
 - filter: ClientIP != '127.0.0.1'
   apply:
     - SetAction("ban")
```

# Waap Rules

For the above two to work, we need to have the two refered waap collection installed : `crowdsec/crs-default` and `crowdsec/vpatch-default`. You need to set hub_branch to ...

```yaml
type: waap-rule
name: crowdsecurity/custom-waf-rule
seclang_rules:
 - SecRule ARGS:ip ";" "t:none,phase:1,log,deny,msg:'semi colon test',id:2"

#$_GET['bar'] matches [0-9]+ AND REQUEST_URI == "/joomla/index.php/component/users/"
#REQUEST_URI == /webui/create_user AND $_POST[username] == "cisco_tac_admin"
rules:
 - target: ARGS
   var: bar
   match: "[0-9]+"
   logic: AND
   sub_rules:
    - target: "REQUEST_URI"
      match: /joomla/index.php/component/users/
 - target: "REQUEST_URI"
   equals: /webui/create_user
   logic: AND
   sub_rules:
    - target: ARGS_POST
      var: username
      equals: cisco_tac_admin
```

