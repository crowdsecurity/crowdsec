## Foreword

Output plugins handle Signal Occurences resulting from bucket overflows.
This allows to either make a simple notification/alerting plugin or fully manage a backend (this is what {{crowdsec.name}} uses to manage SQLite and MySQL).

You can create your own plugins to perform specific actions when a scenario is triggered.

The plugin itself will be compiled into a `.so` and will have its dedicated configuration.

## Interface

Plugins are created in golang and must conform to the following interface :

```go
type Backend interface {
	Insert(types.SignalOccurence) error
	ReadAT(time.Time) ([]map[string]string, error)
	Delete(string) (int, error)
	Init(map[string]string) error
	Flush() error
	Shutdown() error
	DeleteAll() error
	StartAutoCommit() error
}
```

> Startup/shutdown methods

 - `Init` : called at startup time and receives the custom configuration as a string map. Errors aren't fatal, but plugin will be discarded.
 - `Shutdown` : called when {{crowdsec.Name}} is shutting down or restarting


> Writing/Deleting events

 - `Insert` : called every time an overflow happens, receives the `SignalOccurence` as a single parameter. Returned errors are non-fatal and will be logged in warning level.
 - `Delete` : called to delete existing bans. Receives the exact `ip_text` (ban target) to delete. Only used by `cscli ban del`, only relevant for read/write plugins such as database ones.
 - `DeleteAll` : called to delete *all* existing bans. Only used by `cscli ban flush`, only relevant for read/write plugins such as database ones)

> Reading events

 - `ReadAT` : returns the list of bans that where active at the given time. The following keys are relevant in the list returned : source, iptext, reason, bancount, action, cn, as, events_count, until. Only used by `cscli ban list`, only relevant for read/write plugins such as database ones)

> Backend

 - `Flush` is called regulary by crowdsec for each plugin that received events. For example it will be called after each write in `cscli` (as it's one-shot) and every few hundreds of ms / few events in {{crowdsec.name}} itself. It might be a good place to deal with slower write operations.


## Configurations

Each plugin has its own configuration file :

```bash
$ cat config/plugins/backend/dummy.yaml
# name of the plugin, is used by profiles.yaml
name: dummy
# path to the .so
path: ./plugins/backend/dummy.so
# your plugin specific configuration
config:
  some_parameter: some value
  other_parameter: more data
  token: fooobarjajajajaja
```


## Dummy plugin

```go
package main

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

//This is where you would hold your plugin-specific context
type pluginDummy struct {
	//some persistent data
}

func (p *pluginDummy) Shutdown() error {
	return nil
}

func (p *pluginDummy) StartAutoCommit() error {
	return nil
}

func (p *pluginDummy) Init(config map[string]string) error {
	log.Infof("pluginDummy config : %+v ", config)
	return nil
}

func (p *pluginDummy) Delete(target string) (int, error) {
	return 0, nil
}

func (p *pluginDummy) DeleteAll() error {
	return nil
}

func (p *pluginDummy) Insert(sig types.SignalOccurence) error {
	log.Infof("insert signal : %+v", sig)
	return nil
}

func (p *pluginDummy) Flush() error {
	return nil
}

func (p *pluginDummy) ReadAT(timeAT time.Time) ([]map[string]string, error) {
	return nil, nil
}

// New is used by the plugin system to get the context
func New() interface{} {
    return &pluginDummy
    {}
}

// empty main function is mandatory since we are in a main package
func main() {}
```


## Building plugin

```bash
$ go build -buildmode=plugin -o dummy.so
```


## Testing plugin


<details open>
  <summary>Get a test env from fresh crowdsec release</summary>

```bash
$ cd crowdsec-v0.3.0
$ ./test_env.sh
$ cd tests
```
</details>




```bash
$ cp ../../plugins/backend/dummy/dummy.so ./plugins/backend/            
$ cat > config/plugins/backend/dummy.yaml
name: dummy
path: ./plugins/backend/dummy.so
config:
  some_parameter: some value
  other_parameter: more data
  token: fooobarjajajajaja
$ ./crowdsec -c dev.yaml -file test.log -type mylog
...
INFO[06-08-2020 17:21:30] pluginDummy config : map[flush:false max_records:10000 max_records_age:720h other_parameter:more data some_parameter:some value token:fooobarjajajajaja]  
...
INFO[06-08-2020 17:21:30] Starting processing routines                 
...
INFO[06-08-2020 17:21:30] Processing Overflow ...
INFO[06-08-2020 17:21:30] insert signal : {Model:{ID:0 CreatedAt:0001-01-01 00:00:00 +0000 UTC UpdatedAt:0001-01-01 00:00:00 +0000 UTC DeletedAt:<nil>} MapKey:97872dfae02c523577eff8ec8e19706eec5fa21e Scenario:trigger on stuff Bucket_id:summer-field Alert_message:0.0.0.0 performed 'trigger on stuff' (1 events over 59ns) at 2020-08-06 17:21:30.491000439 +0200 CEST m=+0.722674306 Events_count:1 Events_sequence:[{Model:{ID:0 CreatedAt:0001-01-01 00:00:00 +0000 UTC UpdatedAt:0001-01-01 00:00:00 +0000 UTC DeletedAt:<nil>} Time:2020-08-06 17:21:30.491000368 +0200 CEST m=+0.722674247 Source:{Model:{ID:0 CreatedAt:0001-01-01 00:00:00 +0000 UTC UpdatedAt:0001-01-01 00:00:00 +0000 UTC DeletedAt:<nil>} Ip:0.0.0.0 Range:{IP:<nil> Mask:<nil>} AutonomousSystemNumber:0 AutonomousSystemOrganization: Country: Latitude:0 Longitude:0 Flags:map[]} Source_ip:0.0.0.0 Source_range: Source_AutonomousSystemNumber:0 Source_AutonomousSystemOrganization: Source_Country: SignalOccurenceID:0 Serialized:{"ASNNumber":"0","IsInEU":"false","command":"...","cwd":"...":"...","orig_uid":"...","orig_user":"...","parent":"bash","service":"...","source_ip":"...","user":"..."}}] Start_at:2020-08-06 17:21:30.491000368 +0200 CEST m=+0.722674247 BanApplications:[] Stop_at:2020-08-06 17:21:30.491000439 +0200 CEST m=+0.722674306 Source:0xc000248410 Source_ip:0.0.0.0 Source_range:<nil> Source_AutonomousSystemNumber:0 Source_AutonomousSystemOrganization: Source_Country: Source_Latitude:0 Source_Longitude:0 Sources:map[0.0.0.0:{Model:{ID:0 CreatedAt:0001-01-01 00:00:00 +0000 UTC UpdatedAt:0001-01-01 00:00:00 +0000 UTC DeletedAt:<nil>} Ip:0.0.0.0 Range:{IP:<nil> Mask:<nil>} AutonomousSystemNumber:0 AutonomousSystemOrganization: Country: Latitude:0 Longitude:0 Flags:map[]}] Dest_ip: Capacity:0 Leak_speed:0s Whitelisted:false Simulation:false Reprocess:false Labels:map[type:foobar]} 
...
```


## Notes

 - All the calls to the plugin methods are blocking. If you need to perform long running operations, it's the plugin's task to handle the background processing with [tombs](https://godoc.org/gopkg.in/tomb.v2) or such.
 - Due to [a golang limitation](https://github.com/golang/go/issues/31354) you might have to build crowdsec in the same environment as the plugins.



