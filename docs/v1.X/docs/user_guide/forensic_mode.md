## Forensic mode

While {{v1X.crowdsec.name}} can be used to monitor "live" logs, it can as well be used on cold logs.
It is a *great* way to test scenario, detect false positives & false negatives or simply generate reporting on a past time period.

When doing so, {{v1X.crowdsec.name}} will read the logs, extract timestamps from those, so that the scenarios/buckets can be evaluated *relatively* to the log's timestamps. The resulting overflows will be pushed to the API as any other alert, but the timestamp will be the timestamps of the logs, properly allowing you to view the events in their original time line.



!!! warning
        If crowdsec is already running on the same machine, you will need to stop the service beforehand.
        If you don't, crowdsec (even in mode forensic) will try to start a new Local API service, but the port won't be available and fail.


you can run :

```bash
crowdsec -c /etc/crowdsec/user.yaml -file /path/to/your/log/file.log -type log_file_type
```

Where `-file` points to the log file you want to process, and the `-type` is similar to what you would put in your acquisition's label field, for example :

```bash
crowdsec -c /etc/crowdsec/user.yaml -file /var/log/nginx/2019.log -type nginx
crowdsec -c /etc/crowdsec/user.yaml -file /var/log/sshd-2019.log -type syslog
```

When running crowdsec in forensic mode, the alerts will be displayed to stdout, and as well pushed to database :

```bash
# crowdsec  -c /etc/crowdsec/user.yaml  -file /var/log/nginx/nginx-2019.log.1  -type nginx
...
INFO[13-11-2020 13:05:23] Ip 123.206.50.249 performed 'crowdsecurity/http-probing' (11 events over 6s) at 2019-01-01 01:37:32 +0100 CET 
INFO[13-11-2020 13:05:23] Ip 123.206.50.249 performed 'crowdsecurity/http-backdoors-attempts' (2 events over 1s) at 2019-01-01 01:37:33 +0100 CET 
INFO[13-11-2020 13:05:24] (14baeedafc1e44c08b806fc0c1cd92c4/crowdsec) crowdsecurity/http-probing by ip 123.206.50.249 (CN) : 1h ban on Ip 123.206.50.249 
INFO[13-11-2020 13:05:24] (14baeedafc1e44c08b806fc0c1cd92c4/crowdsec) crowdsecurity/http-backdoors-attempts by ip 123.206.50.249 (CN) : 1h ban on Ip 123.206.50.249 
...
```

And as these alerts are as well pushed to database, it mean you can view them in metabase, or using cscli !

