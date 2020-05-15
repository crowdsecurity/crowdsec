<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

<center><a href="https://github.com/crowdsecurity/cs-netfilter-blocker/"><i class="fa fa-github" style="font-size:36px"></i>Netfilter {{plugins.name}}</a></center>


The configuration file is located in `/etc/crowdsec/netfilter-blocker/netfilter-blocker.yaml` :

```
mode: ipset                                      # The mode you want : ipset or TC
dbpath: /var/lib/crowdsec/data/crowdsec.db       # Path to the crowdsec database
piddir: /var/run/                                # PID file, don't touch
update_frequency: 10s                            # 
daemonize: true                                  # Run as a service if true
log_mode: file                                   # Output log to file or stdout
log_dir: /var/log/                               # Folder to write log
```

The log file created by `netfilter-blocker` is called `netfilter-blocker.log`. 