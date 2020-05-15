# Requirements

>Some requirements are needed in order to be able to write your own end-to-end configurations.
>During all this documentation, we are going to show as an exemple how we wrote a full port scan detection scenario (from acqusition to scenario, including parser)

## Create the test environment

First of all, please [download the latest release of {{crowdsec.name}}](https://github.com/crowdsecurity/crowdsec/releases).

Then run the following commands:

```bash
tar xzvf crowdsec-release.tgz
```
```bash
cd ./crowdsec-vX.Y/
```
```bash
./test_env.sh  # the -o is facultative, default is "./tests/"
```
```bash
cd ./tests/
```

The `./test_env.sh` script creates a local (non privileged) working environement for {{crowdsec.name}} and {{cli.name}}.
The deployed environment is intended to write and test parsers and scenarios easily.


<details>
  <summary>Example</summary>

```bash
$ tar xzvf ./crowdsec-release.tgz
$ cd ./crowdsec-v0.0.18/
$ ./test_env.sh 
[09/05/2020:20:02:19][INFO] Creating test arboresence in /tmp/crowdsec-v0.0.18/tests
[09/05/2020:20:02:19][INFO] Arboresence created
[09/05/2020:20:02:19][INFO] Copying needed files for tests environment
[09/05/2020:20:02:19][INFO] Files copied
[09/05/2020:20:02:19][INFO] Setting up configurations
INFO[0000] Failed to open config /tmp/crowdsec-v0.0.18/tests/config/crowdsec-cli/config : open /tmp/crowdsec-v0.0.18/tests/config/crowdsec-cli/config: no such file or directory 
WARN[0000] creating skeleton!                           
INFO[0000] wrote config to /tmp/crowdsec-v0.0.18/tests/config/crowdsec-cli/config  
INFO[0000] wrote config to /tmp/crowdsec-v0.0.18/tests/config/crowdsec-cli/config  
INFO[0000] Wrote new 45625 bytes index to /tmp/crowdsec-v0.0.18/tests/config/crowdsec-cli/.index.json 
INFO[0000] crowdsecurity/syslog-logs : OK               
INFO[0000] crowdsecurity/geoip-enrich : OK              
INFO[0000] crowdsecurity/dateparse-enrich : OK          
INFO[0001] crowdsecurity/linux : OK                     
INFO[0001] /tmp/crowdsec-v0.0.18/tests/config/collections doesn\'t exist, create 
INFO[0001] /tmp/crowdsec-v0.0.18/tests/config/parsers/s00-raw doesn\'t exist, create 
INFO[0001] Enabled parsers : crowdsecurity/syslog-logs  
INFO[0001] /tmp/crowdsec-v0.0.18/tests/config/parsers/s02-enrich doesn\'t exist, create 
INFO[0001] Enabled parsers : crowdsecurity/geoip-enrich 
INFO[0001] Enabled parsers : crowdsecurity/dateparse-enrich 
INFO[0001] Enabled collections : crowdsecurity/linux    
INFO[0001] Enabled crowdsecurity/linux                  
[09/05/2020:20:02:20][INFO] Environment is ready in /tmp/crowdsec-v0.0.18/tests
```

</details>

## &#9432; Reminder

Logs parsing is divided into stage. Each stage are called in the format "sXX-<stage_name>". If a log success in a stage and is configured to go in `next_stage`, then the next stage will process it. Stage process is sorted alphabetically.

Stages and parsers are being processed alphabetically, thus the expected order would be :

```
s00-raw/syslog.yaml

s01-parse/nginx.yaml
s01-parse/apache.yaml

s02-enrich/geoip.yaml
s02-enrich/rdns.yaml
```

### Basics stage

- The first stage (`s00-parse`) is mostly the one that will parsed the begining of your log to say : "This log come from this `source`" where the source can be whatever software that produce logs.
If all your logs are sent to a syslog server, there is a [parser](https://master.d3padiiorjhf1k.amplifyapp.com/author/crowdsecurity/configurations/syslog-logs) that will parse the syslog header to detect the program source.
When the log is processed, the results (ie. capture groups) will be merged in the current {{event.htmlname}} before being sent to the next stage.
 
- The second (`s01-parse`) is the one that will parse the logs and output parsed data and static assigned values. There is currently one parser for one type of software. To parse the logs, regexp or GROK pattern are used. If the parser is configured to go to the [`next_stage`](/references/parsers/#onsuccess), then it will be process by the `enrichment` stage.

- The enrichment `s02-enrich` stage is the one that will enrich the normalized log (we call it an event now that it is normalized) in order to get more information for the heuristic process. This stage can be composed of grok patterns and so on, but as well of plugins that can be writen by the community (geiop enrichment, rdns ...)

### Custom stage

Of course, it is possible to write custom stages. If you want some specific parsing or enrichment to be done after the `s02-enrich` stage, it is possible by creating a new folder `s03-<custom_stage>`. The configuration that will be created in this folder will process the logs configurated to go to `next_stage` in the `s02-enrich` stage. Be careful to write filter that will match incoming event in your custom stage.
