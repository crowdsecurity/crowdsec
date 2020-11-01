# Bouncers


{{v1X.bouncers.Name}} are standalone software pieces in charge of acting upon blocked IPs.

They can either be within the applicative stack, or work out of band :

[nginx blocker](https://github.com/crowdsecurity/cs-nginx-blocker) will check every unknown IP against the database before letting go through or serving a *403* to the user, while a [firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.


You can explore [available {{v1X.bouncers.name}} on the hub]({{v1X.hub.bouncers_url}}), and find below a few of the "main" {{v1X.bouncers.name}} :



## Nginx

### [Installation](https://github.com/crowdsecurity/cs-nginx-bouncer#installation)

### [Configuration](https://github.com/crowdsecurity/cs-nginx-bouncer#configuration)

## Firewall

### [Installation](https://github.com/crowdsecurity/cs-firewall-bouncer#installation)

### [Configuration](https://github.com/crowdsecurity/cs-firewall-bouncer#configuration)

## Custom

### [Installation](https://github.com/crowdsecurity/cs-custom-bouncer#installation)

### [Configuration](https://github.com/crowdsecurity/cs-custom-bouncer#configuration)

## Cloudflare

### [Installation](https://github.com/crowdsecurity/cs-cloudflare-bouncer#installation)

### [Configuration](https://github.com/crowdsecurity/cs-cloudflare-bouncer#configuration)

