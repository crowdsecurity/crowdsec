# Write the acquisition file (optional for test)

In order for your log to be processed by the good parser, it must match the filter that you will configure in your parser file.

The filters of the parsers in the first (`s00-raw`) stage will usually check `evt.Line.Labels.type`, which is the label of your acquisition file :

With an acquisition file like this :

```yaml
filename: /path/to/log/file.log
labels:
  type: my_program
```

 - The log line will enter the parsing pipeline with `evt.Line.Labels.type` set to `my_program`
 - The parsers in the 1st stage (`s00-raw`) are dealing with the raw format, and the program name will end up in `evt.Parsed.program`
 - When the log line arrive the main parsing stage (`s01-parse`), `evt.Parsed.program` will be `my_program`


For example, this file line(s) :

```yaml
filename: /var/log/nginx/access.log
labels:
  type: nginx
```

will be read by this parser :

```yaml
filter: "evt.Parsed.program startsWith 'nginx'"
onsuccess: next_stage
...
```
