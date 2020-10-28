# Write the acquisition file (optional for test)

In order for your log to be processed by the good parser, it must match the filter that you will configure in your parser file.
There are two options:

 - Your logs are written by a syslog server, so you just have to install the [syslog parser](https://master.d3padiiorjhf1k.amplifyapp.com/author/crowdsecurity/configurations/syslog-logs)
 - Your logs are read from a log file. Please add this kind of configuration in your `acquis.yaml` file:

&#9432; the `type` will be matched by the parsers's `filter` in stage `s01-parse`.


```yaml
---
filename: <PATH_TO_YOUR_LOG_FILE>
labels:
  type: <PROGRAM_NAME>

```
Here an example:

<details>
  <summary>Nginx acquisition</summary>

```yaml
---
filename: /var/log/nginx/access.log
labels:
  type: nginx
```

</details>

<details>
  <summary>Nginx parser filter</summary>

```yaml
---
filter: evt.Parsed.program == 'nginx'
```

</details>
