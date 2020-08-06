


# Debugging Scenarios and Parsers

## General Advice

When trying to debug a parser or a scenario :

 - Work on "cold logs" (with the `-file` and `-type` options) rather than live ones
 - Use the `/etc/crowdsec/config/user.yaml` configuration files to have logs on stdout

## Using user-mode configuration

```bash
crowdsec -c /etc/crowdsec/config/user.yaml -file mylogs.log.gz -type syslog
INFO[05-08-2020 16:15:47] Crowdsec v0.3.0-rc3-7525f11975a0107746213862dc41c69e00122ac7 
INFO[05-08-2020 16:15:47] Loading grok library                         
...
WARN[05-08-2020 16:16:12] 182.x.x.x triggered a 4h0m0s ip ban remediation for [crowdsecurity/http-probing]  bucket_id=misty-moon event_time="2019-01-01 22:58:32 +0100 CET" scenario=crowdsecurity/http-probing source_ip=182.x.x.x
...
```

 - `/etc/crowdsec/config/user.yaml` disables demonization and push logs to stdout/stderr
 - `-type` must respect expected log type (ie. `nginx` `syslog` etc.)
 - `-file` must point to a flat file or a gzip file

When processing logs like this, {{crowdsec.name}} runs in "time machine" mode, and relies on the timestamps *in* the logs to evaluate scenarios. You will most likely need the `crowdsecurity/dateparse-enrich` parser for this.


## Testing configurations on live system

If you're playing around with parser/scenarios on a live system, you can use the `-t` (lint) option of {{crowdsec.Name}} to check your configurations validity before restarting/reloading services :

```bash
$ emacs /etc/crowdsec/config/scenarios/ssh-bf.yaml
...
$ crowdsec -c /etc/crowdsec/config/user.yaml -t        
INFO[06-08-2020 13:36:04] Crowdsec v0.3.0-rc3-4cffef42732944d4b81b3e62a03d4040ad74f185 
...
ERRO[06-08-2020 13:36:05] Bad yaml in /etc/crowdsec/config/scenarios/ssh-bf.yaml : yaml: unmarshal errors:
  line 2: field typex not found in type leakybucket.BucketFactory 
FATA[06-08-2020 13:36:05] Failed to load scenarios: Scenario loading failed : bad yaml in /etc/crowdsec/config/scenarios/ssh-bf.yaml : yaml: unmarshal errors:
  line 2: field typex not found in type leakybucket.BucketFactory 
```

Using this, you won't have to kill your running service before you know the scenarios/parsers are at least syntactically correct.


## Using debug

Both scenarios and parsers support a `debug: true|false` option which produce useful debug.

<details>
  <summary>Debug parsing output (expand)</summary>
```bash
DEBU[05-08-2020 15:25:36] eval(evt.Parsed.program == 'nginx') = TRUE    id=lively-smoke name=crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] eval variables:                               id=lively-smoke name=crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36]        evt.Parsed.program = 'nginx'           id=lively-smoke name=crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] Event entering node                           id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] + Grok 'NGINXACCESS' returned 10 entries to merge in Parsed  id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['request'] = '/data.php'             id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['http_user_agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'  id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['http_referer'] = '-'                id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['remote_addr'] = '123.x.x.x'    id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['remote_user'] = '-'                 id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['time_local'] = '01/Jan/2019:01:39:06 +0100'  id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['method'] = 'POST'                   id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['body_bytes_sent'] = '162'           id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['http_version'] = '1.1'              id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] 	.Parsed['status'] = '404'                    id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] .Meta[log_type] = 'http_access-log'           id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] evt.StrTime = '01/Jan/2019:01:39:06 +0100'    id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] Event leaving node : ok                       id=icy-dew name=child-crowdsecurity/nginx-logs stage=s01-parse
DEBU[05-08-2020 15:25:36] child is success, OnSuccess=next_stage, skip  id=lively-smoke name=crowdsecurity/nginx-logs stage=s01-parse
```
</details>


<details>
  <summary>Debug scenario output (expand)</summary>
```bash
DEBU[05-08-2020 16:02:26] eval(evt.Meta.service == 'http' && evt.Meta.http_status in ['404', '403', '400'] && evt.Parsed.static_ressource == 'false') = TRUE  cfg=black-wave file=config/scenarios/http-probing.yaml name=crowdsecurity/http-probing
DEBU[05-08-2020 16:02:26] eval variables:                               cfg=black-wave file=config/scenarios/http-probing.yaml name=crowdsecurity/http-probing
DEBU[05-08-2020 16:02:26]        evt.Meta.service = 'http'              cfg=black-wave file=config/scenarios/http-probing.yaml name=crowdsecurity/http-probing
DEBU[05-08-2020 16:02:26]        evt.Meta.http_status = '404'           cfg=black-wave file=config/scenarios/http-probing.yaml name=crowdsecurity/http-probing
DEBU[05-08-2020 16:02:26]        evt.Parsed.static_ressource = 'false'  cfg=black-wave file=config/scenarios/http-probing.yaml name=crowdsecurity/http-probing
```
</details>


# Test environments

From a [{{crowdsec.name}} release archive]({{crowdsec.download_url}}), you can deploy a test (non-root) environment that is very suitable to write/debug/test parsers and scenarios. Environment is deployed using `./test_env.sh` script from tgz directory, and creates a test environment in `./tests` :

```bash
$ cd crowdsec-v0.3.0/
$ ./test_env.sh 
...
[08/05/2020:04:19:18 PM][INFO] Setting up configurations
INFO[0000] Wrote new 75065 bytes index to config/crowdsec-cli/.index.json 
INFO[0000] crowdsecurity/syslog-logs : OK               
INFO[0000] crowdsecurity/geoip-enrich : OK              
...
INFO[0007] Enabled collections : crowdsecurity/linux    
INFO[0007] Enabled crowdsecurity/linux                  
[08/05/2020:04:19:26 PM][INFO] Environment is ready in /home/bui/github/crowdsec/crowdsec/crowdsec-v0.3.0/tests
$ cd tests 
$ ./cscli -c dev.yaml list 
...
INFO[0000] PARSERS:                                     
-------------------------------------------------------------------------------------------------------
 NAME                            📦 STATUS    VERSION  LOCAL PATH                                      
-------------------------------------------------------------------------------------------------------
 crowdsecurity/geoip-enrich      ✔️  enabled  0.2      config/parsers/s02-enrich/geoip-enrich.yaml     
 crowdsecurity/syslog-logs       ✔️  enabled  0.3      config/parsers/s00-raw/syslog-logs.yaml         
 crowdsecurity/sshd-logs         ✔️  enabled  0.2      config/parsers/s01-parse/sshd-logs.yaml         
 crowdsecurity/dateparse-enrich  ✔️  enabled  0.1      config/parsers/s02-enrich/dateparse-enrich.yaml 
-------------------------------------------------------------------------------------------------------
...
$ ./crowdsec -c dev.yaml -file sshd.log -type syslog
INFO[05-08-2020 16:23:32] Crowdsec v0.3.0-rc3-7525f11975a0107746213862dc41c69e00122ac7 
INFO[05-08-2020 16:23:32] Loading grok library                         
...
```


