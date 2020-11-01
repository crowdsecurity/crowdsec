# Simulation

```bash
$ cscli simulation status
INFO[0000] global simulation: disabled                  
INFO[0000] Scenarios in simulation mode :               
INFO[0000]   - crowdsecurity/ssh-bf                     
```

`cscli simulation` allows to manage a list of scenarios that have their remediation "simulated" : they won't be effective (but will still be showed by `cscli decisions list`). This configuration file is present in `/etc/crowdsec/simulation.yaml`.

You can add and remove scenarios to the simulation list :

```bash
$ cscli simulation enable crowdsecurity/ssh-bf
INFO[0000] simulation mode for 'crowdsecurity/ssh-bf' enabled 
INFO[0000] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
```

But as well turn on "global simulation" : in this case, only scenarios in the exclusion list will have their decisions applied :

```bash

```