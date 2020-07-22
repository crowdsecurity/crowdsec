You can tag some (or all) scenarios as being in **simulation mode**, which is especially useful if :

 - You have one/multiple scenario that might trigger false positives : You can keep track of decisions while not applying automated counter-measures
 - You want *only* specific scenarios to trigger counter-measures



!!! warning "Simulation vs [Whitelists](/write_configurations/whitelist/)"
    Simulation and [Whitelists](/write_configurations/whitelist/) are not to be mixed. [Whitelists](/write_configurations/whitelist/) allows you to purely discard an overflow or a log, while simulation will only "cancel" the action against a peer, while keeping track of events and overflows.


When this happens, the scenarios are still triggered, but the action is prefixed with `simulation:`, which means that blockers won't take action against the peer(s) that triggered the scenario.

Simulation can be managed with [cscli simulation](/cscli/cscli_simulation/) command, and allows you to have settings such as _"all in simulation except scenarios X,Y,Z"_ or _"only scenarios X,Y,Z in simulation mode"_ :

 - `cscli simulation enable` : Globally enables simulation (all scenarios will be in simulation mode)
 - `cscli simulation enable author/my_scenario` : Enables simulation only for a specific scenario


```bash
$ cscli simulation enable crowdsecurity/http-probing
INFO[0000] simulation mode for 'crowdsecurity/http-probing' enabled 

$ cscli simulation status                                     
INFO[0000] global simulation: disabled                  
INFO[0000] Scenarios in simulation mode :               
INFO[0000]   - crowdsecurity/http-probing

$ tail -f /var/log/crowdsec.log
...
WARN[21-07-2020 11:29:01] 127.0.0.1 triggered a 4h0m0s ip simulation:ban remediation for [crowdsecurity/http-probing]  bucket_id=restless-sound event_time="2020-07-21 11:29:01.817545253 +0200 CEST m=+3.794547062" scenario=crowdsecurity/http-probing source_ip=127.0.0.1

$ cscliban list 
1 local decisions:
+--------+-----------+----------------------------+------+----------------+---------+----+--------+------------+
| SOURCE |    IP     |           REASON           | BANS |     ACTION     | COUNTRY | AS | EVENTS | EXPIRATION |
+--------+-----------+----------------------------+------+----------------+---------+----+--------+------------+
| local  | 127.0.0.1 | crowdsecurity/http-probing |    2 | simulation:ban |         | 0  |     22 | 3h59m24s   |
+--------+-----------+----------------------------+------+----------------+---------+----+--------+------------+

```

The simulation settings can be found in the `simulation.yaml` file of your configuration directory :


```yaml
#if simulation is false, exclusions are the only ones in learning,
#if simulation is true, exclusions are the only ones *not* in learning
simulation: false
exclusions:
- crowdsecurity/http-crawl-non_statics
- crowdsecurity/http-probing
```


