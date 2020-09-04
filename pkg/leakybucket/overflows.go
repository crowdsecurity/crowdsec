package leakybucket

import (
	"fmt"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// for now return the struct directly in order to compare between returned struct
func NewSource(evt types.Event, l *Leaky) types.Source {
	src := types.Source{}
	if _, ok := evt.Meta["source_ip"]; ok {
		source_ip := evt.Meta["source_ip"]
		src.Ip = net.ParseIP(source_ip)
		if v, ok := evt.Enriched["ASNNumber"]; ok {
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
				l.logger.Errorf("Declared range %s of %s can't be parsed", v, src.Ip.String())
			} else if ipNet != nil {
				src.Range = *ipNet
				l.logger.Tracef("Valid range from %s : %s", src.Ip.String(), src.Range.String())
			}
		}
	}
	if l.Scope != "IP" {
		src.Scope = l.Scope
		if _, ok := evt.Meta[l.Scope]; ok {
			src.Value = evt.Meta[l.Scope]
		}
	}
	return src
}

func NewAlert(l *Leaky, queue *Queue) types.Alert {
	var (
		am      string
		scope   string = ""
		sources map[string]types.Source
	)

	l.logger.Debugf("Overflow (start: %s, end: %s)", l.First_ts, l.Ovflw_ts)

	alert := types.Alert{
		Mapkey:      l.Mapkey,
		Bucket_id:   l.Uuid,
		Scenario:    l.Name,
		StartAt:     l.First_ts,
		StopAt:      l.Ovflw_ts,
		Sources:     make(map[string]types.Source),
		Labels:      l.BucketConfig.Labels,
		Capacity:    l.Capacity,
		Reprocess:   l.Reprocess,
		LeakSpeed:   l.Leakspeed,
		EventsCount: l.Total_count,
	}

	for _, evt := range queue.Queue {
		// check if the source is already known,
		// If we don't know the source then add it to the known list of sources
		//either it's a collection of logs, or a collection of past overflows being reprocessed.
		//one overflow can have multiple sources for example
		switch evt.Type {
		case types.LOG:
			src := NewSource(evt, l)
			if scope == "" {
				scope = src.Scope
			}
			if src.Scope != scope {
				l.logger.Errorf("Event has multiple Sources with different Scopes: %s, %s %s != %s", alert.Scenario, alert.Bucket_id, src.Scope, scope)
			}
			sources[src.Value] = src //this might overwrite an already existing source, but in that case, the source should be the same.
		case types.OVFLW:
			for k, v := range evt.Overflow.Sources {
				sources[k] = v
			}
		}
	}

	//Management of Alert.Message
	if len(alert.Sources) > 1 {
		am = fmt.Sprintf("%d Sources on scope %s", len(alert.Sources))
	} else if len(alert.Sources) == 1 {

	} else {
		am = "UNKNOWN"
	}
	am += fmt.Sprintf(" performed '%s' (%d events over %s) at %s", l.Name, l.Total_count, l.Ovflw_ts.Sub(l.First_ts), l.Ovflw_ts)
	alert.Message = am
	return alert
}
