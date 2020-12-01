# Events

An `Event` is the runtime representation of an item being processed by crowdsec, it can be: 

 - a log line being parsed

 - an overflow being reprocessed


The `Event` object is modified by parsers, scenarios, and directly via user [statics expressions](/Crowdsec/v1/references/parsers/#statics) (for example).

The representation of the object can be found here : 

[Event object documentation](https://pkg.go.dev/github.com/crowdsecurity/crowdsec/pkg/types#Event)

## LOG relevant fields

 - `Type` is `types.LOG`
 - `Whitelisted` : if `true` the LOG or OVFLW will be dropped
 - `Line` : representation of the raw line
    - `Raw` : the raw line representation
    - `Src` : a label for the source
    - `Time` : acquisition timestamp
    - `Labels` : the static labels (from acquis.yaml) associated to the source
    - `Process`: if set to false, processing of line will stop
 - `Parsed` : a `map[string]string` that can be used during parsing and enrichment. This is where GROK patterns will output their captures by default
 - `Enriched` : a `map[string]string` that can be used during parsing and enrichment. This is where enrichment functions will output their captures by default
 - `Meta` : a `map[string]string` that can be used to store *important* information about a log. This map is serialized into DB when storing event.
 - `Overflow` : representation of an Overflow if `Type` is set to `OVFLW`
 - `Time` : processing timestamp
 - `StrTime` : string representation of log timestamp. Can be set by parsers that capture timestamp in logs. Will be automatically processed by `crowdsecurity/dateparse-enrich` when processing logs in forensic mode to set `MarshaledTime`
 - `MarshaledTime` : if non-empty, the event's timestamp that will be used when processing buckets (for forensic mode)
 
## OVERFLOW relevant fields

 - `Type` is `types.OVFLW`
 - `Whitelisted` : if `true` the LOG or OVFLW will be dropped
 - `Overflow` : representation of an Overflow if `Type` is set to `OVFLW`
 - `Time` : processing timestamp
 - `StrTime` : string representation of log timestamp. Can be set by parsers that capture timestamp in logs. Will be automatically processed by `crowdsecurity/dateparse-enrich` when processing logs in forensic mode to set `MarshaledTime`
 - `MarshaledTime` : if non-empty, the event's timestamp that will be used when processing buckets (for forensic mode)
 - `Overflow` : 
    - `Whitelisted` : if true the OVFLW will be dropped
    - `Reprocess` : if true, the OVFLOW will be reprocessed (inference)
    - `Sources` : a `map[string]models.Source` representing the distinct sources that triggered the overflow, with their types and values.
    - `Alert` and `APIAlerts` : representation of the signals that will be sent to LAPI.

