# Bouncers


{{v1X.bouncers.Name}} are standalone software pieces in charge of acting upon a decision taken by crowdsec : block an IP, present a captcha, enforce MFA on a given user, etc.

They can either be within the applicative stack, or work out of band :

[nginx bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer) will check every unknown IP against the local API before letting go through or serving a *403* to the user, while a [firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) will simply "add" malevolent IPs to nftables/ipset set of blacklisted IPs.

Bouncers rely on [crowdsec's Local API](/Crowdsec/v1/localAPI/) to be able to get informations about a given IP or such.


You can explore [available {{v1X.bouncers.name}} on the hub]({{v1X.hub.bouncers_url}}).


To be able for your {{v1X.bouncers.Name}} to communicate with the local API, you have to generate an API token with `cscli` and put it in your {{v1X.bouncers.Name}} configuration file:

```bash
$ sudo cscli bouncers add testBouncer
Api key for 'testBouncer':

   6dcfe93f18675265e905aef390330a35

Please keep this key since you will not be able to retrive it!
```

Note: this command must be run on the server where the local API is installed (or at least with a cscli that has valid credentials to communicate with the database used by the API).