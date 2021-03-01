# Acquisition format

The `crowdsec_service` section of configuration supports `acquisition_path` and `acquisition_dir` (>1.0.7).

The default setting is to have `acquisition_path` pointing to `/etc/crowdsec/acquis.yaml`.

`acquisition_dir` can be set to point to a directory where every `.yaml` file is considered as a valid acquisition configuration file.



The acquisition file(s) define which source of information (ie. files or journald streams) are read by crowdsec at runtime.
The file is a list of object representing groups of files to read, with the following properties.

A least one of :

 - filename: a string representing the path to a file (globbing supported)
 - filenames: a list of string represent paths to files (globbing supported)
 - journalctl_filter: a list of string passed as arguments to `journalctl`

And a `labels` object with a field `type` indicating the log's type :
```yaml
filenames:
  - /var/log/nginx/access-*.log
  - /var/log/nginx/error.log
labels:
  type: nginx
---
filenames:
  - /var/log/auth.log
labels:
  type: syslog
---
journalctl_filter:
 - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog

```

The `labels.type` is *important* as it is what will determine which parser will try to process the logs. 

The log won't be processed by the syslog parser if its type is not syslog :
```bash
$ cat /etc/crowdsec/parsers/s00-raw/syslog-logs.yaml 
filter: "evt.Line.Labels.type == 'syslog'"
...
```

On the other hand, nginx tends to write its own logs without using syslog :
```bash
$ cat /etc/crowdsec/parsers/s01-parse/nginx-logs.yaml 
filter: "evt.Parsed.program startsWith 'nginx'"
...
```

If for example your nginx was logging via syslog, you need to set its `labels.type` to `syslog` so that it's first parsed by the syslog parser, and *then* by the nginx parser (notice they are in different stages).

