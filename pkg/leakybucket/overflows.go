package leakybucket

import (
	"fmt"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

//SourceFromEvent extracts and formats a valid models.Source object from an Event
func SourceFromEvent(evt types.Event, leaky *Leaky) (models.Source, error) {
	src := models.Source{}

	switch leaky.scopeType.Scope {
	case types.Range, types.Ip:
		if v, ok := evt.Meta["source_ip"]; ok {
			if net.ParseIP(v) == nil {
				return src, fmt.Errorf("scope is %s but '%s' isn't a valid ip", leaky.scopeType.Scope, v)
			} else {
				src.IP = v
			}
		} else {
			return src, fmt.Errorf("scope is %s but Meta[source_ip] doesn't exist", leaky.scopeType.Scope)
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
		if v, ok := evt.Meta["SourceRange"]; ok && v != "" {
			_, ipNet, err := net.ParseCIDR(v)
			if err != nil {
				return src, fmt.Errorf("Declared range %s of %s can't be parsed", v, src.IP)
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
				return src, errors.Wrapf(err, "while running scope filter")
			}

			value, ok := retValue.(string)
			if !ok {
				value = ""
			}
			src.Value = &value
		} else {
			return src, fmt.Errorf("empty scope information")
		}
	}
	return src, nil
}

//EventsFromQueue iterates the queue to collect & prepare meta-datas from alert
func EventsFromQueue(queue *Queue) []*models.Event {

	events := []*models.Event{}

	for _, evt := range queue.Queue {
		if evt.Meta == nil {
			continue
		}
		meta := models.Meta{}
		for k, v := range evt.Meta {
			subMeta := models.MetaItems0{Key: k, Value: v}
			meta = append(meta, &subMeta)
		}

		ovflwEvent := models.Event{
			Meta:      meta,
			Timestamp: &evt.MarshaledTime,
		}
		events = append(events, &ovflwEvent)
	}
	return events
}

//alertDefaultDecision generates a default (4h ban) decision for a given source
func alertDefaultDecision(source models.Source) (*models.Decision, error) {
	var decision models.Decision

	decision.Duration = new(string)
	*decision.Duration = "4h"

	if *source.Scope == types.Ip {
		srcAddr := net.ParseIP(source.IP)
		if srcAddr == nil {
			return nil, fmt.Errorf("can't parse ip %s", source.IP)
		}
		decision.StartIP = int64(types.IP2Int(srcAddr))
		decision.EndIP = decision.StartIP
	} else if *source.Scope == types.Range {
		srcAddr, srcRange, err := net.ParseCIDR(*source.Value)
		if err != nil {
			return nil, fmt.Errorf("can't parse range %s", *source.Value)
		}
		decision.StartIP = int64(types.IP2Int(srcAddr))
		decision.EndIP = int64(types.IP2Int(types.LastAddress(srcRange)))

	}

	decision.Scope = source.Scope
	decision.Value = source.Value
	decision.Origin = new(string)
	*decision.Origin = "crowdsec"
	decision.Type = new(string)
	*decision.Type = "ban"
	return &decision, nil
}

//alertFormatSource iterates over the queue to collect sources
func alertFormatSource(leaky *Leaky, queue *Queue) (map[string]models.Source, string, error) {
	var sources map[string]models.Source = make(map[string]models.Source)
	var source_type string

	for _, evt := range queue.Queue {
		src, err := SourceFromEvent(evt, leaky)
		if err != nil {
			return nil, "", errors.Wrapf(err, "while extracting scope from bucket %s", leaky.Name)
		}
		if source_type == types.Undefined {
			source_type = *src.Scope
		}
		if *src.Scope != source_type {
			return nil, "",
				fmt.Errorf("event has multiple source types : %s != %s", *src.Scope, source_type)
		}
		sources[*src.Value] = src
	}
	return sources, source_type, nil
}

//NewAlert will generate a RuntimeAlert and its APIAlert(s) from a bucket that overflowed
func NewAlert(leaky *Leaky, queue *Queue) (types.RuntimeAlert, error) {

	var runtimeAlert types.RuntimeAlert

	leaky.logger.Infof("Overflow (start: %s, end: %s)", leaky.First_ts, leaky.Ovflw_ts)
	/*
		Craft the models.Alert that is going to be duplicated for each source
	*/
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
	startAt := string(start_at)
	stopAt := string(stop_at)
	apiAlert := models.Alert{
		Scenario:        &leaky.Name,
		ScenarioHash:    &leaky.hash,
		ScenarioVersion: &leaky.scenarioVersion,
		Capacity:        &capacity,
		EventsCount:     &EventsCount,
		Leakspeed:       &leakSpeed,
		Message:         new(string),
		StartAt:         &startAt,
		StopAt:          &stopAt,
		Simulated:       new(bool),
	}

	if leaky.BucketConfig == nil {
		return runtimeAlert, fmt.Errorf("leaky.BucketConfig is nil")
	}

	//Get the sources from Leaky/Queue
	sources, source_scope, err := alertFormatSource(leaky, queue)
	if err != nil {
		return runtimeAlert, errors.Wrap(err, "unable to collect sources from bucket")
	}
	runtimeAlert.Sources = sources
	//Include source info in format string
	sourceStr := ""
	if len(sources) > 1 {
		sourceStr = fmt.Sprintf("%d Sources on scope.", len(sources))
	} else if len(sources) == 1 {
		for k, _ := range sources {
			sourceStr = k
			break
		}
	} else {
		sourceStr = "UNKNOWN"
	}
	*apiAlert.Message = fmt.Sprintf("%s %s performed '%s' (%d events over %s) at %s", source_scope, sourceStr, leaky.Name, leaky.Total_count, leaky.Ovflw_ts.Sub(leaky.First_ts), leaky.Ovflw_ts)
	//Get the events from Leaky/Queue
	apiAlert.Events = EventsFromQueue(queue)

	//Loop over the Sources and generate appropriate number of ApiAlerts
	for srcName, srcValue := range sources {
		log.Infof("handling %s", srcName)
		newApiAlert := apiAlert
		srcCopy := srcValue
		newApiAlert.Source = &srcCopy
		decision, err := alertDefaultDecision(srcValue)
		decision.Scenario = new(string)
		*decision.Scenario = leaky.Name
		if err != nil {
			return runtimeAlert, errors.Wrap(err, "failed to build decision")
		}
		log.Printf("decision : %s", spew.Sdump(decision))
		newApiAlert.Decisions = []*models.Decision{decision}
		if err := newApiAlert.Validate(strfmt.Default); err != nil {
			log.Errorf("Generated alerts isn't valid")
			log.Errorf("->%s", spew.Sdump(newApiAlert))
			log.Fatalf("error : %s", err)
		}
		runtimeAlert.APIAlerts = append(runtimeAlert.APIAlerts, newApiAlert)
	}

	runtimeAlert.Alert = &runtimeAlert.APIAlerts[0]
	log.Printf("returning alert with %d api alerts", len(runtimeAlert.APIAlerts))
	return runtimeAlert, nil
}
