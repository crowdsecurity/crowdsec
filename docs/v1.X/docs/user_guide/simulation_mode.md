# Simulation

```bash
$ sudo cscli simulation status
INFO[0000] global simulation: disabled                  
INFO[0000] Scenarios in simulation mode :               
INFO[0000]   - crowdsecurity/ssh-bf                     
```

`cscli simulation` allows to manage a list of scenarios that have their remediation "simulated" : they won't be effective (but will still be showed by `cscli decisions list`). This configuration file is present in `/etc/crowdsec/simulation.yaml`.

You can add and remove scenarios to the simulation list :

```bash
$ sudo cscli simulation enable crowdsecurity/ssh-bf
INFO[0000] simulation mode for 'crowdsecurity/ssh-bf' enabled 
INFO[0000] Run 'sudo systemctl reload crowdsec' for the new configuration to be effective. 
$ sudo systemctl reload crowdsec
$ sudo tail -f /var/log/crowdsec.log
  ....
time="01-11-2020 14:08:58" level=info msg="Ip 1.2.3.6 performed 'crowdsecurity/ssh-bf' (6 events over 986.769µs) at 2020-11-01 14:08:58.575885389 +0100 CET m=+437.524832750"
time="01-11-2020 14:08:58" level=info msg="Ip 1.2.3.6 decision : 1h (simulation) ban"
  ....

$  cscli decisions list
+----+----------+--------------+-----------------------------------+------------+---------+----+--------+------------------+
| ID |  SOURCE  | SCOPE:VALUE  |              REASON               |   ACTION   | COUNTRY | AS | EVENTS |    EXPIRATION    |
+----+----------+--------------+-----------------------------------+------------+---------+----+--------+------------------+
|  4 | crowdsec | Ip:1.2.3.6   | crowdsecurity/ssh-bf              | (simul)ban | US      |    |      6 | 59m38.293036072s |
+----+----------+--------------+-----------------------------------+------------+---------+----+--------+------------------+

```

But as well turn on "global simulation" : in this case, only scenarios in the exclusion list will have their decisions applied.