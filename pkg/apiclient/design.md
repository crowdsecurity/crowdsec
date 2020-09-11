api-client : Client to consume APIL / APIC rest api.


Used by :
 - cscli : for adding, listing, deleting alerts and/or decisions add/del/list
 - crowdsec : for pushing alerts to APIL
 - blockers : to either get a stream of decisions, or to query APIL/APIC on a specific IP


Authentications :
 - login/password for cscli/crowdsec
 - api token for blockers

Global methods :
 - add an alert with(out) decision(s)
 - list alerts with(out) decisions


Architecture :
 - represent the entities and such directly in the interface ? ie.


```golang
Client.Alerts.Add(types.Alert{})
Client.Alerts.List()
Client.Alerts.List(AlertsFilters{source_as_name: "xxxx"})
```

```golang
 CsApiCfg := {
     main_url : ...
     version : ...
     /*does it makes sense to have endpoints in the config ?*/
     login_endpoint : ...
     decisions_endpoint : ...
 }
 ApiClient := csApi.New()
 if err := ApiClient.SetConfig(CsApiConfig)
```



----------------------------------------

# Interface

```golang
type ApiClient struct {
    /*exposed methods*/
    Decisions ApiDecisions
    Alerts ApiAlerts
    Auth ApiAuth
    Consensus ApiConsensus
    /*dat context*/
    client *http.Client
    //...
}

type service struct {
    client *http.Client
}

type Response struct {
    *http.Response
    //add our pagination stuff
    NextPage int
    //...
}

type ListOpts struct {
    Page int
    PerPage int
}


```


```golang
/* Decisions */
type ApiDecisions service

type DecisionsListOpts struct {
    scope_equals string `"json:scope"`
    value_equals string `"json:value"`
    type_equals string `"json:type"`
    ListOpts
}

type DecisionsDeleteOpts struct {
    scope_equals string `"json:scope"`
    value_equals string `"json:value"`
    type_equals string `"json:type"`
    ListOpts
}

func (s *ApiDecisions) StartStream(ctx context.Context) (*Response, error)
func (s *ApiDecisions) StopStream(ctx context.Context) (*Response, error)
func (s *ApiDecisions) StreamPoll(ctx context.Context) ([]Decision, []Decision, *Response, error)
func (s *ApiDecisions) List(ctx context.Context, Opts DecisionsListOpts) ([]Decision,  *Response, error)
func (s *ApiDecisions) Delete(ctx context.Context, Opts DecisionsDeleteOpts) ([]Decision,  *Response, error)

```

```golang
/* Alerts */
type ApiAlerts interface {
    StartStream(ctx context.Context) http.Response, error
    StopStream(ctx context.Context) http.Response, error
    StreamPoll(ctx context.Context) []Alert, []Alert, http.Response, error
    List(ctx context.Context, AlertsFilter) []Alert, http.Response, error
    Delete(ctx context.Context, AlertsFilter) []Alert, http.Response, error
    Add(ctx context.Context, []Alert) http.Response, error
}
```

```golang
/* Auth */
type ApiAuth interface {
    Register(ctx context.Context, machine_id string, password string) http.Response, error
    Auth(ctx context.Context, machine_id string, password string) http.Response, error
    Ping(ctx context.Context) http.Response, error
}
```


# Api methods exposition

## /decision/stream


```golang
//Start a stream : GET /decisions/stream?startup=True
Client.Decisions.StartStream() error
//Stop a stream : DELETE /decisions/stream
Client.Decisions.StopStream() error
//Returns decisions (new, deleted) : GET /decisions/stream
Client.Decisions.StreamPoll() []Decision, []Decision, error
```

## /ping

```golang
Client.Ping() error
```

## /decisions

```golang
type DecisionsFilter struct {
    scope_equals string `"json:scope"`
    value_equals string `"json:value"`
    type_equals string `"json:type"`
}
```

### GET
```golang
//Returns decisions according to DecisionFilter : GET /decisions?scope=xx&value=yy
Client.Decisions.List(DecisionsFilter) []Decision, error
```

### DELETE
```golang
//Returns decisions according to DecisionFilter : DELETE /decisions?scope=xx&value=yy
Client.Decisions.Delete(DecisionsFilter) []Decision, error
```

## /decisions/{decision_id}

```golang
//Delete matching decision(s) : DELETE /decisions/Decision.api_id
Client.Decisions.Delete(Decision) int, error
```

## /alerts

```golang
type AlertsFilter struct {
    scope_equals string `"json:scope"`
    value_equals string `"json:value"`
    type_equals string `"json:type"`
    scenario_equals string `"json:scenario"`
}
//Returns decisions according to DecisionFilter : GET /alerts?scope=xx&value=yy
Client.Alerts.List(AlertsFilter) []Alert, error
```

## /watchers

### POST (register)

```golang
//POST /watchers, error : REFUSED, PENDING
Client.Auth.Register(machine_id string, password string) error
```

### DELETE (unregister)

```golang
//POST /watchers, error : ERROR
Client.Auth.Unregister(machine_id string, password string) error
```


## /watchers/login

```golang
Client.Auth.Login(machine_id string, password string) error
```

## /topx

```golang
//Get topX (new, deleted) from central API
Client.Consensus.GetTopX() []Decision, []Decision, error
```

## /apic/watchers (copy/pasta for blockers)


### POST

```golang
type WatcherInfo struct {
    machine_id string //the machine ID
    hash string //hashed machine information for uniqueness (ie. source_ip + user-agent + whatever)
}
//Report new watcher : 
Client.Consensus.ReportWatchers([]WatcherInfo) error
```

### DELETE

```golang
//DELETE /api/watchers/{WatcherInfo.api_id}
Client.Consensus.DeleteWatchers([]WatcherInfo) error
```




