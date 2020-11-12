# bouncers


{{v0X.bouncers.Name}} are standalone software pieces in charge of acting upon blocked IPs.

They can either within the applicative stack, or work out of band :

[nginx blocker](https://github.com/crowdsecurity/cs-nginx-blocker) will check every unknown IP against the database before letting go through or serving a *403* to the user, while a [netfilter blocker](https://github.com/crowdsecurity/cs-netfilter-blocker) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.


You can explore [available {{v0X.bouncers.name}} on the hub]({{v0X.hub.plugins_url}}), and find below a few of the "main" {{v0X.bouncers.name}} :

