# Requirements

>Some requirements are needed in order to be able to write your own end-to-end configurations.
>During all this documentation, we are going to show as an exemple how we wrote a full port scan detection scenario (from acqusition to scenario, including parser)

## Create the test environment

First of all, please [download the latest release of {{v1X.crowdsec.name}}](https://github.com/crowdsecurity/crowdsec/releases).

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

The `./test_env.sh` script creates a local (non privileged) working environement for {{v1X.crowdsec.name}} and {{v1X.cli.name}}.
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
