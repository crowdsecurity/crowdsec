# Write the acquisition file (optional for test)

In order for your log to be processed by the good parser, it must match the filter that you will configure in your parser file.
There is two option:

 - Your logs are wrote from a syslog server, so you just have to install the [syslog parser](https://master.d3padiiorjhf1k.amplifyapp.com/author/crowdsecurity/configurations/syslog-logs)
 - You're log are read from a log file. Please add this kind of configuration in your `acquis.yaml` file:

&#9432; the `prog_name` is the one that the parser in `s01-parse` filter will need to match.


```
---
filename: <PATH_TO_YOUR_LOG_FILE>
labels:
  prog_name: <PROGRAM_NAME>

```
Here an example:

<details>
  <summary>Nginx acquisition</summary>

```yaml
---
filename: /var/log/nginx/access.log
labels:
  prog_name: nginx
```

</details>

<details>
  <summary>Nginx parser filter</summary>

```yaml
---
filter: evt.Parsed.program == 'nginx'
```

</details>
