## cscli install

Install configuration(s) from hub

### Synopsis


Install configuration from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).


### Examples

```
cscli install [type] [config_name]
```

### Options

```
  -d, --download-only   Only download packages, don't enable
      --force           Force install : Overwrite tainted and outdated files
  -h, --help            help for install
```

### Options inherited from parent commands

```
  -c, --config string   path to crowdsec config file (default "/etc/crowdsec/config/default.yaml")
      --debug           Set logging to debug.
      --error           Set logging to error.
      --info            Set logging to info.
  -o, --output string   Output format : human, json, raw. (default "human")
      --warning         Set logging to warning.
```

### SEE ALSO

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli install collection](cscli_install_collection.md)	 - Install given collection
* [cscli install parser](cscli_install_parser.md)	 - Install given parser
* [cscli install postoverflow](cscli_install_postoverflow.md)	 - Install given postoverflow parser
* [cscli install scenario](cscli_install_scenario.md)	 - Install given scenario


