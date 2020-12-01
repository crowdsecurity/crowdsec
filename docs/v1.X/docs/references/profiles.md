# Profiles configurations

The profiles configuration (`/etc/crowdsec/profiles.yaml`) allow to configure what kind of remediation needs to be applied when a scenario is triggered :

The configuration file is a yaml file that looks like :

```yaml
name: default_ip_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
on_success: break
```

Each YAML object in the file contains a list of `models.Decision` that contains :

## `name`

```yaml
name: foobar
```

A label for the profile (used in logging)

## `debug`

```yaml
debug: true
```

A boolean flag that provides contextual debug.

## `filters`

```yaml
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Session"
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
```

If any `filter` of the list returns `true`, the profile is elligible and the `decisions` will be applied.

## `decisions`

```yaml
decisions:
 - type: captcha
   duration: 1h
   scope: custom_app1_captcha
 - type: ban
   duration: 2h
```

If the profile applies, decisions objects will be created for each of the sources that triggered the scenario.

It is a list of `models.Decision` objects. The following fields, when present, allows to alter the resulting decision :

 - `scope` : defines the scope of the resulting decision
 - `duration` : defines for how long will the decision be valid
 - `type` : defines the type of the remediation that will be applied by available {{v1X.bouncers.htmlname}}, for example `ban`, `captcha`
 - `value` : define a hardcoded value for the decision (ie. `1.2.3.4`)

## `on_success`

```yaml
on_success: break
```

If the profile applies and `on_success` is set to `break`, decisions processing will stop here and it won't evaluate against following profiles.

## `on_failure`

```yaml
on_failure: break
```

If the profile didn't apply and `on_failure` is set to `break`, decisions processing will stop here and it won't evaluate against following profiles.

