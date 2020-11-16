# Crowdsec

Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database.

## Getting Started

Before start using docker image, we suggest you to read our documentation to understand all [crowdsec concepts](https://docs.crowdsec.net/).

### Prerequisities


In order to run this container you'll need docker installed.

* [Windows](https://docs.docker.com/windows/started)
* [OS X](https://docs.docker.com/mac/started/)
* [Linux](https://docs.docker.com/linux/started/)

### How to use ?

#### Build

`git clone https://github.com/crowdsecurity/crowdsec.git && cd crowdsec`
`docker build -t crowdsec .`

#### Run

The container is built with [default configuration](https://github.com/crowdsecurity/crowdsec/blob/master/config/config.yaml) with `daemonize:false` and `log_media:false`, you need to do some actions before :

* Specify collections|scenarios|parsers/postoverflows to install via the environment variables (by default [`crowdsecurity/linux`](https://hub.crowdsec.net/author/crowdsecurity/collections/linux) in installed)
* Mount volumes to specify your configuration
* Mount volumes to specify your log files that would be ingested by crowdsec (set up in acquis.yaml)
* Mount other volumes : if you want to share the database for example

```shell
docker run -d --name crowdsec \
    -v config.yaml:/etc/crowdsec/config.yaml \
    -v acquis.yaml:/etc/crowdsec/acquis.yaml \
    -e COLLECTIONS="crowdsecurity/sshd"
    -v /var/log/auth.log:/var/log/auth.log \
    -v /path/mycustom.log:/var/log/mycustom.log \
```

#### Exemple

I have my own configuration :
```shell
user@cs ~/crowdsec/config $ ls
acquis.yaml  config.yaml
```

Here is my acquis.yaml file:
```shell
filenames:
 - /logs/auth.log
 - /logs/syslog
labels:
  type: syslog
---
filename: /logs/apache2/*.log
labels:
  type: apache2
```

So, I want to run crowdsec with :
* My configuration files
* Ingested my path logs specified in acquis.yaml
* Share the crowdsec sqlite database with my host (You need to create empty file first, otherwise docker will create a directory instead of simple file)

```shell
touch /path/myDatabase.db
docker run -d --name crowdsec \
    -v config.yaml:/etc/crowdsec/config.yaml \
    -v acquis.yaml:/etc/crowdsec/acquis.yaml \
    -v /var/log/auth.log:/logs/auth.log \
    -v /var/log/syslog.log:/logs/syslog.log \
    -v /var/log/apache:/logs/apache \
    -v /path/myDatabase.db:/var/lib/crowdsec/data/crowdsec.db # Database path set up in config.yaml file (if you use sqlite)
    -e COLLECTIONS="crowdsecurity/apache2"
```

### Environment Variables

* `COLLECTIONS` - collections to install from the [hub](https://hub.crowdsec.net/browse/#collections), separated by space : `-e COLLECTIONS="crowdsecurity/linux crowdsecurity/apache2"`
* `SCENARIOS`   - scenarios to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e SCENARIOS="crowdsecurity/http-bad-user-agent crowdsecurity/http-xss-probing"`
* `PARSERS`     - parsers to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e PARSERS="crowdsecurity/http-logs crowdsecurity/modsecurity"`

### Volumes

* `/var/lib/crowdsec/data/` - Directory where all crowdsec data (Databases) is located

* `/etc/crowdsec/` - Directory where all crowdsec configurations are located

#### Useful File Locations

* `/usr/local/bin/crowdsec` - Crowdsec binary
  
* `/usr/local/bin/cscli` - Crowdsec CLI binary to interact with crowdsec

## Find Us

* [GitHub](https://github.com/crowdsecurity/crowdsec)

## Contributing

Please read [contributing](https://docs.crowdsec.net/Crowdsec/v1/contributing/) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE) file for details.