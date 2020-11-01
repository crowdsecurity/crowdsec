# Simulation

Simulation config is in `/etc/crowdsec/simulation.yaml` and looks like :

```yaml
#if simulation is set to 'true' here, *all* scenarios will be in simulation unless in exclusion list
simulation: false
#exclusion to the policy - here, the scenarios that are in simulation mode
exclusions:
- crowdsecurity/ssh-bf

```

