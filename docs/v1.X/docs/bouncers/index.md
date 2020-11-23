# Bouncers


{{v1X.bouncers.Name}} are standalone software pieces in charge of acting upon blocked IPs.

They can either be within the applicative stack, or work out of band :

[nginx bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer) will check every unknown IP against the database before letting go through or serving a *403* to the user, while a [firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.


You can explore [available {{v1X.bouncers.name}} on the hub]({{v1X.hub.bouncers_url}}).


To be able for your {{v1X.bouncers.Name}} to communicate with the local API, you have to generate an API token with `cscli` and put it in your {{v1X.bouncers.Name}} configuration file:

```bash
$ cscli bouncers add testBouncer
Api key for 'testBouncer':

   6dcfe93f18675265e905aef390330a35

Please keep this key since you will not be able to retrive it!
```

Note: this command must be run on the server where the local API in installed.