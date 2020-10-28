## cscli api

Crowdsec API interaction

### Synopsis


Allow to register your machine into crowdsec API to send and receive signal.
		

### Examples

```

cscli api register      # Register to Crowdsec API
cscli api pull          # Pull malevolant IPs from Crowdsec API
cscli api reset         # Reset your machines credentials
cscli api enroll        # Enroll your machine to the user account you created on Crowdsec backend
cscli api credentials   # Display your API credentials

```

### Options

```
  -h, --help   help for api
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
* [cscli api credentials](cscli_api_credentials.md)	 - Display api credentials
* [cscli api enroll](cscli_api_enroll.md)	 - Associate your machine to an existing crowdsec user
* [cscli api pull](cscli_api_pull.md)	 - Pull crowdsec API TopX
* [cscli api register](cscli_api_register.md)	 - Register on Crowdsec API
* [cscli api reset](cscli_api_reset.md)	 - Reset password on CrowdSec API


