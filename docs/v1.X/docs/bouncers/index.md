# Bouncers


{{v1X.bouncers.Name}} are standalone software pieces in charge of acting upon blocked IPs.

They can either be within the applicative stack, or work out of band :

[nginx bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer) will check every unknown IP against the database before letting go through or serving a *403* to the user, while a [firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.


You can explore [available {{v1X.bouncers.name}} on the hub]({{v1X.hub.bouncers_url}}), and find below a few of the "main" {{v1X.bouncers.name}} :

