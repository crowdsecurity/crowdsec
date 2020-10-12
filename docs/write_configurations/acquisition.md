# What is acquisition

Acquisition configuration (`/etc/crowdsec/config/acquis.yaml`) defines what log files are read by {{crowdsec.name}}. As log files determines what {{crowdsec.name}} can detect, it is a simple yet crucial part of the configuration.

This `acquisition.yaml` file is composed of sections that look like this :

```yaml
filename: /var/log/myservice/foobar.log
labels:
  type: myservice
---
filenames:
  - /var/log/myservice/*.log
  - /var/log/something/else.log
labels:
  type: myservice
```

Each section indicate :

 - path(s) to a log file (or a regular expression for globing)
 - label(s) indicating the log's type

While the path(s) is straightforward, the `labels->type` will depend on log's format.
If you're using syslog format, `labels->type` can simply be set to `syslog`, as it contains the program name itself. If your logs are written directly by a daemon (ie. nginx) with its own format, it must be set accordingly to the parser : `nginx` for nginx etc.

If you don't know to which value you need to set the `labels->type`. First check if logs are written in syslog format (it's the case for a lot of services on linux) : in this case simply set it to `syslog`. If the service **- and only if -** the service write its own logs, have a look at the associated parser :

```bash
$ head /etc/crowdsec/config/parsers/s01-parse/mysql-logs.yaml 
...
#labels->type must be set to 'mysql'
filter: "evt.Parsed.program == 'mysql'"
...
```

!!! warning
    Properly picking the log type is crucial. If the `labels->type` is wrong, your logs won't be parsed and thus will be discarded. You can see if your logs are parsed from `cscli metrics`.


```yaml
---
filename: <PATH_TO_YOUR_LOG_FILE>
labels:
  type: <PROGRAM_NAME>

```
Here are some examples:

<details>
  <summary>Nginx acquisition</summary>

```yaml
---
filename: /var/log/nginx/*.log
labels:
  type: nginx
```

</details>



<details>
  <summary>sshd acquisition</summary>

```yaml
#Generated acquisition file - wizard.sh (service: sshd) / files : /var/log/auth.log
filenames:
  - /var/log/auth.log
labels:
  type: syslog
---
```

</details>

<details>
  <summary>mysql acquisition</summary>

```yaml
#Generated acquisition file - wizard.sh (service: mysql) / files : /var/log/mysql/error.log
filenames:
  - /var/log/mysql/error.log
labels:
  type: mysql
```

</details>
