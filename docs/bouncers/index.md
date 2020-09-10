# bouncers


{{bouncers.Name}} are standalone software pieces in charge of acting upon blocked IPs.

They can either be within the applicative stack, or work out of band :

[nginx bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer) will check every unknown IP against the database before letting go through or serving a *403* to the user, while a [netfilter bouncer](https://github.com/crowdsecurity/cs-netfilter-bouncer) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.


You can explore [available {{bouncers.name}} on the hub]({{hub.plugins_url}}), and find below a few of the "main" {{bouncers.name}}.

