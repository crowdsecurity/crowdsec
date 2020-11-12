# Requirements

> - Having read and understood [`crowdsec` concepts](/Crowdsec/v1/getting_started/concepts/)

> - Some requirements are needed in order to be able to write your own end-to-end configurations.

> - During all this documentation, we are going to show as an exemple how we wrote a full port scan detection scenario (from acqusition to scenario, including parser)


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
$ cd ./crowdsec-v*/
$ ./test_env.sh 
[12/11/2020:11:45:19][INFO] Creating test arboresence in /tmp/crowdsec-v1.0.0/tests
[12/11/2020:11:45:19][INFO] Arboresence created
[12/11/2020:11:45:19][INFO] Copying needed files for tests environment
[12/11/2020:11:45:19][INFO] Files copied
[12/11/2020:11:45:19][INFO] Setting up configurations
INFO[0000] Machine 'test' created successfully          
INFO[0000] API credentials dumped to '/tmp/crowdsec-v1.0.0/tests/config/local_api_credentials.yaml' 
INFO[0000] Wrote new 73826 bytes index to /tmp/crowdsec-v1.0.0/tests/config/hub/.index.json 
INFO[0000] crowdsecurity/syslog-logs : OK               
INFO[0000] crowdsecurity/geoip-enrich : OK              
INFO[0000] downloading data 'https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/GeoLite2-City.mmdb' in '/tmp/crowdsec-v1.0.0/tests/data/GeoLite2-City.mmdb' 
INFO[0002] downloading data 'https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/GeoLite2-ASN.mmdb' in '/tmp/crowdsec-v1.0.0/tests/data/GeoLite2-ASN.mmdb' 
INFO[0003] crowdsecurity/dateparse-enrich : OK          
INFO[0003] crowdsecurity/sshd-logs : OK                 
INFO[0004] crowdsecurity/ssh-bf : OK                    
INFO[0004] crowdsecurity/sshd : OK                      
WARN[0004] crowdsecurity/sshd : overwrite               
INFO[0004] crowdsecurity/linux : OK                     
INFO[0004] /tmp/crowdsec-v1.0.0/tests/config/collections doesn't exist, create 
INFO[0004] Enabled parsers : crowdsecurity/syslog-logs  
INFO[0004] Enabled parsers : crowdsecurity/geoip-enrich 
INFO[0004] Enabled parsers : crowdsecurity/dateparse-enrich 
INFO[0004] Enabled parsers : crowdsecurity/sshd-logs    
INFO[0004] Enabled scenarios : crowdsecurity/ssh-bf     
INFO[0004] Enabled collections : crowdsecurity/sshd     
INFO[0004] Enabled collections : crowdsecurity/linux    
INFO[0004] Enabled crowdsecurity/linux                  
INFO[0004] Run 'systemctl reload crowdsec' for the new configuration to be effective. 
[12/11/2020:11:45:25][INFO] Environment is ready in /tmp/crowdsec-v1.0.0/tests

```


