# scenario tests

```
$ make build
$ cd tests/.../
$ git clone git@github.com:JohnDoeCrowdSec/hub.git hub
$ ./cracra.sh -all
```

For the tests to run :
 - crowdsec must be built
 - ./hub/ must be a valid hub directory (ie `git clone git@github.com:JohnDoeCrowdSec/hub.git hub`)

Each test is a directory starting by `0` containing :
 - a logfile `file.log`
 - a list of enabled parsers `parsers.yaml`
 - a list of enabled scenarios `scenarios.yaml`
 - a `success.sqlite` file that is a list of sqlite commands that must run successfuly
 - a `label` file containing the label of the input file (ie. `type:syslog` or `prog_name:nginx`)

A test is successfull when the agent, started with said parsers.yaml,scenarios.yaml,postoverflows.yaml produces a sqlite database conform to success.sqlite after being injected with the `file.log` in time-machine mode.

## parsers.yaml

As tests are run using time-machine mode, the `timemachine.yaml` parsers is mandatory or you will be getting errors.

```
$ cat 01ssh/parsers.yaml 
 - filename: ./hub/parsers/s00-raw/crowdsec/syslog-parse.yaml
   stage: s00-raw
 - filename: ./hub/parsers/s01-parse/crowdsec/sshd-logs.yaml
   stage: s01-parse
 - filename: ./hub/parsers/s02-enrich/crowdsec/timemachine.yaml
   stage: s02-enrich
```

postoverflows and scenarios follows the same logic.
