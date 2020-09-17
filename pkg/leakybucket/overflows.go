package leakybucket

import (
	"fmt"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

func metaFromEvent(evt types.Event) models.Meta {
	var meta models.Meta

	if evt.Meta == nil {
		return nil
	}
	for k, v := range evt.Meta {
		subMeta := models.MetaItems0{Key: k, Value: v}
		meta = append(meta, &subMeta)
	}
	return meta
}

// for now return the struct directly in order to compare between returned struct
func NewSource(evt types.Event, leaky *Leaky) models.Source {
	src := models.Source{}

	//log.Printf("source type : %s", leaky.scopeType.Scope)
	switch leaky.scopeType.Scope {
	case types.Range, types.Ip:
		source_ip := evt.Meta["source_ip"]
		if net.ParseIP(source_ip) == nil {
			log.Warningf("%s isn't a valid ip", source_ip)
		} else {
			src.IP = source_ip
		}
		src.Scope = &leaky.scopeType.Scope
		if v, ok := evt.Enriched["ASNumber"]; ok {
			src.AsNumber = v
		}
		if v, ok := evt.Enriched["IsoCode"]; ok {
			src.Cn = v
		}
		if v, ok := evt.Enriched["ASNOrg"]; ok {
			src.AsName = v
		}
		if v, ok := evt.Enriched["Latitude"]; ok {
			l, err := strconv.ParseFloat(v, 32)
			if err != nil {
				log.Warningf("bad latitude %s : %s", v, err)
			}
			src.Latitude = float32(l)
		}
		if v, ok := evt.Enriched["Longitude"]; ok {
			l, err := strconv.ParseFloat(v, 32)
			if err != nil {
				log.Warningf("bad longitude %s : %s", v, err)
			}
			src.Longitude = float32(l)
		}
		if v, ok := evt.Meta["SourceRange"]; ok {
			_, ipNet, err := net.ParseCIDR(v)
			if err != nil {
				leaky.logger.Errorf("Declared range %s of %s can't be parsed", v, src.IP)
			} else if ipNet != nil {
				src.Range = ipNet.String()
				leaky.logger.Tracef("Valid range from %s : %s", src.IP, src.Range)
			}
		}
		if leaky.scopeType.Scope == types.Ip {
			src.Value = &src.IP
		} else if leaky.scopeType.Scope == types.Range {
			src.Value = &src.Range
		}
	default:
		if leaky.scopeType.RunTimeFilter != nil {
			retValue, err := expr.Run(leaky.scopeType.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &evt}))
			if err != nil {
				leaky.logger.Errorf("Scope filter failed at runtime. Don't konw how to handle this: %s", err)
			}

			value, ok := retValue.(string)
			if !ok {
				value = ""
			}
			src.Value = &value
		} else {
			log.Warningf("Empty scope information")
		}
	}
	return src
}

func NewAlert(leaky *Leaky, queue *Queue) types.RuntimeAlert {
	var (
		am      string
		scope   string = types.Undefined
		sources map[string]models.Source
	)

	leaky.logger.Debugf("Overflow (start: %s, end: %s)", leaky.First_ts, leaky.Ovflw_ts)

	start_at, err := leaky.First_ts.MarshalText()
	if err != nil {
		log.Warningf("failed to marshal ts %s : %s", leaky.First_ts.String(), err)
	}
	stop_at, err := leaky.Last_ts.MarshalText()
	if err != nil {
		log.Warningf("failed to marshal ts %s : %s", leaky.First_ts.String(), err)
	}
	capacity := int32(leaky.Capacity)
	EventsCount := int32(leaky.Total_count)
	leakSpeed := leaky.Leakspeed.String()
	message := "stuff happened"
	startAt := string(start_at)
	stopAt := string(stop_at)
	apiAlert := models.Alert{
		Scenario:        &leaky.Name,
		ScenarioHash:    &leaky.hash,
		ScenarioVersion: &leaky.scenarioVersion,
		Capacity:        &capacity,
		EventsCount:     &EventsCount,
		Leakspeed:       &leakSpeed,
		Message:         &message, //TBD
		StartAt:         &startAt,
		StopAt:          &stopAt,

		//TBD(m): Decisions
		//TBD(m): Meta

		//TBD: Labels
	}
	alert := types.RuntimeAlert{
		Mapkey:    leaky.Mapkey,
		BucketId:  leaky.Uuid,
		Sources:   make(map[string]models.Source),
		APIAlerts: []models.Alert{apiAlert},
		Reprocess: leaky.Reprocess,
	}

	alert.Alert = &alert.APIAlerts[0]

	sources = make(map[string]models.Source)
	/*we're going to iterate over the Queue of events for two things :
	- collecting sources
	- collecting meta-data
	*/
	for _, evt := range queue.Queue {
		// check if the source is already known,
		//If we don't know the source then add it to the known list of sources
		//either it's a collection of logs, or a collection of past overflows being reprocessed.
		//one overflow can have multiple sources for example
		switch evt.Type {
		case types.LOG:
			src := NewSource(evt, leaky)
			if scope == types.Undefined {
				scope = *src.Scope
			}
			if *src.Scope != scope {
				leaky.logger.Errorf("Event has multiple Sources with different Scopes: %s, %s %s != %s", *alert.Alert.Scenario, alert.BucketId, *src.Scope, scope)
			}
			sources[*src.Value] = src //this might overwrite an already existing source, but in that case, the source should be the same.
			//Iterate over the meta of the Events to aggregate them
			ovflwEvent := models.Event{
				Meta:      metaFromEvent(evt),
				Timestamp: &evt.MarshaledTime,
			}
			alert.Alert.Events = append(alert.Alert.Events, &ovflwEvent)
		case types.OVFLW:
			for k, v := range evt.Overflow.Sources {
				sources[k] = v
			}
		default:
			log.Fatalf("unknown event type : %d", evt.Type)
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
	alert.Alert.Message = &am

	//log.Printf("The event is : %s", spew.Sdump(alert))
	return alert
}
