# Local API

The Local API (LAPI) is a core component of {{v1X.crowdsec.name}} and has a few essential missions :

 - Allow crowdsec machines to push alerts & decisions to a database
 - Allow bouncers to consume said alerts & decisions from database
 - Allow `cscli` to view add or delete decisions


## Authentication

There is two kinds of authentication to the local API :
 - Bouncers : they authenticate with a simple API key and can only read decisions
 - Machines : they authenticate with a login&password and can not only read decisions, but create new ones



See the [Local API public documentation]({{v1X.lapi.swagger}})

