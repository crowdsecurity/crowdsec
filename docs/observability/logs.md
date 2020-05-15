Logs concern everything that happens to {{crowdsec.Name}} itself (startup, configuration, events like IP ban or an alert, shutdown, and so on).

By default, logs are written to `{{crowdsec.main_log}}`, in text format. 

<details>
  <summary>Logs example</summary>


```bash
time="12-05-2020 15:34:21" level=info msg="setting loglevel to info"
time="12-05-2020 15:34:21" level=info msg="Crowdsec v0.0.19-9ae496aa9cfd008513976a096accc7cfc43f2d9b"
time="12-05-2020 15:34:21" level=warning msg="Loading prometheus collectors"
time="12-05-2020 15:34:23" level=warning msg="no version in /etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml, assuming '1.0'"
time="12-05-2020 15:34:23" level=warning msg="Starting profiling and http server"
time="12-05-2020 15:34:24" level=warning msg="no version in /etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml, assuming '1.0'"
time="12-05-2020 15:34:24" level=info msg="Node has no name,author or description. Skipping."
time="12-05-2020 15:34:24" level=info msg="Loading 2 parser nodes" file=/etc/crowdsec/config/parsers/s00-raw/syslog-logs.yaml
time="12-05-2020 15:34:24" level=warning msg="no version in /etc/crowdsec/config/parsers/s01-parse/nginx-logs.yaml, assuming '1.0'"
time="12-05-2020 15:34:24" level=info msg="Loading 3 parser nodes" file=/etc/crowdsec/config/parsers/s01-parse/nginx-logs.yaml
time="12-05-2020 15:34:24" level=warning msg="no version in /etc/crowdsec/config/parsers/s01-parse/sshd-logs.yaml, assuming '1.0'"
time="13-05-2020 17:42:53" level=warning msg="24 existing LeakyRoutine"
time="13-05-2020 18:02:51" level=info msg="Flushed 1 expired entries from Ban Application"
time="13-05-2020 18:12:46" level=info msg="Flushed 1 expired entries from Ban Application"
time="13-05-2020 18:20:29" level=warning msg="11.11.11.11 triggered a 4h0m0s ip ban remediation for [crowdsecurity/ssh-bf]" bucket_id=winter-shadow event_time="2020-05-13 18:20:29.855776892 +0200 CEST m=+96112.558589990" scenario=crowdsecurity/ssh-bf source_ip=11.11.11.11
time="13-05-2020 18:31:26" level=warning msg="22.22.22.22 triggered a 4h0m0s ip ban remediation for [crowdsecurity/ssh-bf]" bucket_id=dry-mountain event_time="2020-05-13 18:31:26.989769738 +0200 CEST m=+96769.692582872" scenario=crowdsecurity/ssh-bf source_ip=22.22.22.22
time="13-05-2020 18:41:10" level=warning msg="16 existing LeakyRoutine"
time="13-05-2020 18:46:19" level=warning msg="33.33.33.33 triggered a 4h0m0s ip ban remediation for [crowdsecurity/iptables-scan-multi_ports]" bucket_id=holy-paper event_time="2020-05-13 18:46:19.825693323 +0200 CEST m=+97662.528506421" scenario=crowdsecurity/iptables-scan-multi_ports source_ip=33.33.33.33
```

</details>