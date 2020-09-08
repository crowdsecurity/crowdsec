package leakybucket

import (
	"fmt"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// for now return the struct directly in order to compare between returned struct
func NewSource(evt types.Event, leaky *Leaky) types.Source {
	src := types.Source{}
	if _, ok := evt.Meta["source_ip"]; ok {
		source_ip := evt.Meta["source_ip"]
		src.Ip = net.ParseIP(source_ip)
		if v, ok := evt.Enriched["ASNumber"]; ok {
			src.AutonomousSystemNumber = v
		}
		if v, ok := evt.Enriched["IsoCode"]; ok {
			src.Country = v
		}
		if v, ok := evt.Enriched["ASNOrg"]; ok {
			src.AutonomousSystemOrganization = v
		}
		if v, ok := evt.Enriched["Latitude"]; ok {
			src.Latitude, _ = strconv.ParseFloat(v, 32)
		}
		if v, ok := evt.Enriched["Longitude"]; ok {
			src.Longitude, _ = strconv.ParseFloat(v, 32)
		}
		if v, ok := evt.Meta["SourceRange"]; ok {
			_, ipNet, err := net.ParseCIDR(v)
			if err != nil {
				leaky.logger.Errorf("Declared range %s of %s can't be parsed", v, src.Ip.String())
			} else if ipNet != nil {
				src.Range = *ipNet
				leaky.logger.Tracef("Valid range from %s : %s", src.Ip.String(), src.Range.String())
			}
		}
		if leaky.scopeType.Scope == types.Undefined || leaky.scopeType.Scope == types.Ip {
			src.ScopeData.Scope = types.Ip
			src.ScopeData.Value = source_ip
		}

	}
	src.ScopeData.Scope = leaky.scopeType.Scope

	if leaky.scopeType.Scope == types.Filter {
		retValue, err := expr.Run(leaky.scopeType.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &evt}))
		if err != nil {
			leaky.logger.Errorf("Scope filter failed at runtime. Don't konw how to handle this: %s", err)
		}

		value, ok := retValue.(string)
		if !ok {
			value = ""
		}
		src.ScopeData.Value = value
	}
	// 	src.Scope = leaky.Scope
	// 	if _, ok := evt.Meta[leaky.Scope]; ok {
	// 		src.Value = evt.Meta[leaky.Scope]
	// 	}
	// }
	return src
}

func NewAlert(leaky *Leaky, queue *Queue) types.Alert {
	var (
		am      string
		scope   string = types.Undefined
		sources map[string]types.Source
	)

	leaky.logger.Debugf("Overflow (start: %s, end: %s)", leaky.First_ts, leaky.Ovflw_ts)

	alert := types.Alert{
		Mapkey:      leaky.Mapkey,
		Bucket_id:   leaky.Uuid,
		Scenario:    leaky.Name,
		StartAt:     leaky.First_ts,
		StopAt:      leaky.Ovflw_ts,
		Sources:     make(map[string]types.Source),
		Labels:      leaky.BucketConfig.Labels,
		Capacity:    leaky.Capacity,
		Reprocess:   leaky.Reprocess,
		LeakSpeed:   leaky.Leakspeed,
		EventsCount: leaky.Total_count,
	}

	sources = make(map[string]types.Source)
	for _, evt := range queue.Queue {
		// check if the source is already known,
		// If we don't know the source then add it to the known list of sources
		//either it's a collection of logs, or a collection of past overflows being reprocessed.
		//one overflow can have multiple sources for example
		switch evt.Type {
		case types.LOG:
			src := NewSource(evt, leaky)
			if scope == types.Undefined {
				scope = src.ScopeData.Scope
			}
			if src.ScopeData.Scope != scope {
				leaky.logger.Errorf("Event has multiple Sources with different Scopes: %s, %s %s != %s", alert.Scenario, alert.Bucket_id, src.ScopeData.Scope, scope)
			}
			sources[src.ScopeData.Value] = src //this might overwrite an already existing source, but in that case, the source should be the same.
		case types.OVFLW:
			for k, v := range evt.Overflow.Sources {
				sources[k] = v
			}
		}
	}

	alert.Sources = sources
	//Management of Alert.Message
	if len(alert.Sources) > 1 {
		am = fmt.Sprintf("%d Sources on scope.", len(alert.Sources))
	} else if len(alert.Sources) == 1 {

	} else {
		am = "UNKNOWN"
	}
	am += fmt.Sprintf(" performed '%s' (%d events over %s) at %s", leaky.Name, leaky.Total_count, leaky.Ovflw_ts.Sub(leaky.First_ts), leaky.Ovflw_ts)
	alert.Message = am
	return alert
}
