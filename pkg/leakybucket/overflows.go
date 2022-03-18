package leakybucket

import (
	"fmt"
	"net"
	"sort"
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
func SourceFromEvent(evt types.Event, leaky *Leaky) (map[string]models.Source, error) {
	srcs := make(map[string]models.Source)
	/*if it's already an overflow, we have properly formatted sources.
	we can just twitch them to reflect the requested scope*/
	if evt.Type == types.OVFLW {

		for k, v := range evt.Overflow.Sources {

			/*the scopes are already similar, nothing to do*/
			if leaky.scopeType.Scope == *v.Scope {
				srcs[k] = v
				continue
			}

			/*The bucket requires a decision on scope Range */
			if leaky.scopeType.Scope == types.Range {
				/*the original bucket was target IPs, check that we do have range*/
				if *v.Scope == types.Ip {
					src := models.Source{}
					src.AsName = v.AsName
					src.AsNumber = v.AsNumber
					src.Cn = v.Cn
					src.Latitude = v.Latitude
					src.Longitude = v.Longitude
					src.Range = v.Range
					src.Value = new(string)
					src.Scope = new(string)
					*src.Scope = leaky.scopeType.Scope
					*src.Value = ""
					if v.Range != "" {
						*src.Value = v.Range
					}
					if leaky.scopeType.RunTimeFilter != nil {
						retValue, err := expr.Run(leaky.scopeType.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &evt}))
						if err != nil {
							return srcs, errors.Wrapf(err, "while running scope filter")
						}
						value, ok := retValue.(string)
						if !ok {
							value = ""
						}
						src.Value = &value
					}
					if *src.Value != "" {
						srcs[*src.Value] = src
					} else {
						log.Warningf("bucket %s requires scope Range, but none was provided. It seems that the %s wasn't enriched to include its range.", leaky.Name, *v.Value)
					}
				} else {
					log.Warningf("bucket %s requires scope Range, but can't extrapolate from %s (%s)",
						leaky.Name, *v.Scope, *v.Value)
				}
			}
		}
		return srcs, nil
	}
	src := models.Source{}
	switch leaky.scopeType.Scope {
	case types.Range, types.Ip:
		v, ok := evt.Meta["source_ip"]
		if !ok {
			return srcs, fmt.Errorf("scope is %s but Meta[source_ip] doesn't exist", leaky.scopeType.Scope)
		}
		if net.ParseIP(v) == nil {
			return srcs, fmt.Errorf("scope is %s but '%s' isn't a valid ip", leaky.scopeType.Scope, v)
		}
		src.IP = v
		src.Scope = &leaky.scopeType.Scope
		if v, ok := evt.Enriched["ASNumber"]; ok {
			src.AsNumber = v
		} else if v, ok := evt.Enriched["ASNNumber"]; ok {
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
				return srcs, fmt.Errorf("Declared range %s of %s can't be parsed", v, src.IP)
			}
			if ipNet != nil {
				src.Range = ipNet.String()
				leaky.logger.Tracef("Valid range from %s : %s", src.IP, src.Range)
			}
		}
		if leaky.scopeType.Scope == types.Ip {
			src.Value = &src.IP
		} else if leaky.scopeType.Scope == types.Range {
			src.Value = &src.Range
			if leaky.scopeType.RunTimeFilter != nil {
				retValue, err := expr.Run(leaky.scopeType.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &evt}))
				if err != nil {
					return srcs, errors.Wrapf(err, "while running scope filter")
				}

				value, ok := retValue.(string)
				if !ok {
					value = ""
				}
				src.Value = &value
			}
		}
		srcs[*src.Value] = src
	default:
		if leaky.scopeType.RunTimeFilter == nil {
			return srcs, fmt.Errorf("empty scope information")
		}
		retValue, err := expr.Run(leaky.scopeType.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &evt}))
		if err != nil {
			return srcs, errors.Wrapf(err, "while running scope filter")
		}

		value, ok := retValue.(string)
		if !ok {
			value = ""
		}
		src.Value = &value
		src.Scope = new(string)
		*src.Scope = leaky.scopeType.Scope
		srcs[*src.Value] = src
	}
	return srcs, nil
}

//EventsFromQueue iterates the queue to collect & prepare meta-datas from alert
func EventsFromQueue(queue *Queue) []*models.Event {

	events := []*models.Event{}

	for _, evt := range queue.Queue {
		if evt.Meta == nil {
			continue
		}
		meta := models.Meta{}
		//we want consistence
		skeys := make([]string, 0, len(evt.Meta))
		for k := range evt.Meta {
			skeys = append(skeys, k)
		}
		sort.Strings(skeys)
		for _, k := range skeys {
			v := evt.Meta[k]
			subMeta := models.MetaItems0{Key: k, Value: v}
			meta = append(meta, &subMeta)
		}

		/*check which date to use*/
		ovflwEvent := models.Event{
			Meta: meta,
		}
		//either MarshaledTime is present and is extracted from log
		if evt.MarshaledTime != "" {
			ovflwEvent.Timestamp = &evt.MarshaledTime
		} else if !evt.Time.IsZero() { //or .Time has been set during parse as time.Now().UTC()
			ovflwEvent.Timestamp = new(string)
			raw, err := evt.Time.MarshalText()
			if err != nil {
				log.Warningf("while marshaling time '%s' : %s", evt.Time.String(), err)
			} else {
				*ovflwEvent.Timestamp = string(raw)
			}
		} else {
			log.Warningf("Event has no parsed time, no runtime timestamp")
		}

		events = append(events, &ovflwEvent)
	}
	return events
}

//alertFormatSource iterates over the queue to collect sources
func alertFormatSource(leaky *Leaky, queue *Queue) (map[string]models.Source, string, error) {
	var sources map[string]models.Source = make(map[string]models.Source)
	var source_type string

	log.Debugf("Formatting (%s) - scope Info : scope_type:%s / scope_filter:%s", leaky.Name, leaky.scopeType.Scope, leaky.scopeType.Filter)

	for _, evt := range queue.Queue {
		srcs, err := SourceFromEvent(evt, leaky)
		if err != nil {
			return nil, "", errors.Wrapf(err, "while extracting scope from bucket %s", leaky.Name)
		}
		for key, src := range srcs {
			if source_type == types.Undefined {
				source_type = *src.Scope
			}
			if *src.Scope != source_type {
				return nil, "",
					fmt.Errorf("event has multiple source types : %s != %s", *src.Scope, source_type)
			}
			sources[key] = src
		}
	}
	return sources, source_type, nil
}

func EventToLabel(Queue) {

}

//NewAlert will generate a RuntimeAlert and its APIAlert(s) from a bucket that overflowed
func NewAlert(leaky *Leaky, queue *Queue) (types.RuntimeAlert, error) {
	var runtimeAlert types.RuntimeAlert

	leaky.logger.Tracef("Overflow (start: %s, end: %s)", leaky.First_ts, leaky.Ovflw_ts)
	/*
		Craft the models.Alert that is going to be duplicated for each source
	*/
	start_at, err := leaky.First_ts.MarshalText()
	if err != nil {
		log.Warningf("failed to marshal start ts %s : %s", leaky.First_ts.String(), err)
	}
	stop_at, err := leaky.Ovflw_ts.MarshalText()
	if err != nil {
		log.Warningf("failed to marshal ovflw ts %s : %s", leaky.First_ts.String(), err)
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
		Simulated:       &leaky.Simulated,
	}
	if leaky.BucketConfig == nil {
		return runtimeAlert, fmt.Errorf("leaky.BucketConfig is nil")
	}

	//give information about the bucket
	runtimeAlert.Mapkey = leaky.Mapkey

	//Get the sources from Leaky/Queue
	sources, source_scope, err := alertFormatSource(leaky, queue)
	if err != nil {
		return runtimeAlert, errors.Wrap(err, "unable to collect sources from bucket")
	}
	runtimeAlert.Sources = sources
	//Include source info in format string
	sourceStr := "UNKNOWN"
	if len(sources) > 1 {
		sourceStr = fmt.Sprintf("%d sources", len(sources))
	} else if len(sources) == 1 {
		for k := range sources {
			sourceStr = k
			break
		}
	}

	*apiAlert.Message = fmt.Sprintf("%s %s performed '%s' (%d events over %s) at %s", source_scope, sourceStr, leaky.Name, leaky.Total_count, leaky.Ovflw_ts.Sub(leaky.First_ts), leaky.Last_ts)
	//Get the events from Leaky/Queue
	apiAlert.Events = EventsFromQueue(queue)

	//Loop over the Sources and generate appropriate number of ApiAlerts
	for _, srcValue := range sources {
		newApiAlert := apiAlert
		srcCopy := srcValue
		newApiAlert.Source = &srcCopy
		if v, ok := leaky.BucketConfig.Labels["remediation"]; ok && v == "true" {
			newApiAlert.Remediation = true
		}

		if err := newApiAlert.Validate(strfmt.Default); err != nil {
			log.Errorf("Generated alerts isn't valid")
			log.Errorf("->%s", spew.Sdump(newApiAlert))
			log.Fatalf("error : %s", err)
		}
		runtimeAlert.APIAlerts = append(runtimeAlert.APIAlerts, newApiAlert)
	}

	if len(runtimeAlert.APIAlerts) > 0 {
		runtimeAlert.Alert = &runtimeAlert.APIAlerts[0]
	}

	if leaky.Reprocess {
		runtimeAlert.Reprocess = true
	}
	return runtimeAlert, nil
}
