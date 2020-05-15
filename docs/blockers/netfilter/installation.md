<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">


<center><a href="https://github.com/crowdsecurity/cs-netfilter-blocker/"><i class="fa fa-github" style="font-size:36px"></i>Netfilter {{plugins.name}}</a></center>


First, please [download the latest release](https://github.com/crowdsecurity/cs-netfilter-blocker/releases/latest) of our netfilter {{plugins.name}}.

Then run the following commands:

```bash
tar xzvf cs-netfilter-blocker.tgz
```
```bash
cd cs-netfilter-blocker/
```
```bash
sudo ./install.sh
```


When an IP is referenced in the SQLite database, it will be put in an ipset blacklist to ban that IP.


&#9432; IPv4 and IPv6 are supported.