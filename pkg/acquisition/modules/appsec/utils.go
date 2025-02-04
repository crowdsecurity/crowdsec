package appsecacquisition

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/coraza/v3/collection"
	"github.com/crowdsecurity/coraza/v3/types/variables"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func AppsecEventGenerationGeoIPEnrich(src *models.Source) error {

	if src == nil || src.Scope == nil || *src.Scope != types.Ip {
		return errors.New("source is nil or not an IP")
	}

	//GeoIP enrich
	asndata, err := exprhelpers.GeoIPASNEnrich(src.IP)

	if err != nil {
		return err
	} else if asndata != nil {
		record := asndata.(*geoip2.ASN)
		src.AsName = record.AutonomousSystemOrganization
		src.AsNumber = fmt.Sprintf("%d", record.AutonomousSystemNumber)
	}

	cityData, err := exprhelpers.GeoIPEnrich(src.IP)
	if err != nil {
		return err
	} else if cityData != nil {
		record := cityData.(*geoip2.City)
		src.Cn = record.Country.IsoCode
		src.Latitude = float32(record.Location.Latitude)
		src.Longitude = float32(record.Location.Longitude)
	}

	rangeData, err := exprhelpers.GeoIPRangeEnrich(src.IP)
	if err != nil {
		return err
	} else if rangeData != nil {
		record := rangeData.(*net.IPNet)
		src.Range = record.String()
	}
	return nil
}

func AppsecEventGeneration(inEvt types.Event, request *http.Request) (*types.Event, error) {
	// if the request didnd't trigger inband rules, we don't want to generate an event to LAPI/CAPI
	if !inEvt.Appsec.HasInBandMatches {
		return nil, nil
	}

	evt := types.Event{}
	evt.Type = types.APPSEC
	evt.Process = true
	sourceIP := inEvt.Parsed["source_ip"]
	source := models.Source{
		Value: &sourceIP,
		IP:    sourceIP,
		Scope: ptr.Of(types.Ip),
	}

	// Enrich source with GeoIP data
	if err := AppsecEventGenerationGeoIPEnrich(&source); err != nil {
		log.Errorf("unable to enrich source with GeoIP data : %s", err)
	}

	// Build overflow
	evt.Overflow.Sources = make(map[string]models.Source)
	evt.Overflow.Sources[sourceIP] = source

	alert := models.Alert{}
	alert.Capacity = ptr.Of(int32(1))
	alert.Events = make([]*models.Event, len(evt.Appsec.GetRuleIDs()))

	metas, errors := alertcontext.AppsecEventToContext(inEvt.Appsec, request)
	if len(errors) > 0 {
		for _, err := range errors {
			log.Errorf("failed to generate appsec context: %s", err)
		}
	}

	alert.Meta = metas

	alert.EventsCount = ptr.Of(int32(len(alert.Events)))
	alert.Leakspeed = ptr.Of("")
	alert.Scenario = ptr.Of(inEvt.Appsec.MatchedRules.GetName())
	alert.ScenarioHash = ptr.Of(inEvt.Appsec.MatchedRules.GetHash())
	alert.ScenarioVersion = ptr.Of(inEvt.Appsec.MatchedRules.GetVersion())
	alert.Simulated = ptr.Of(false)
	alert.Source = &source
	msg := fmt.Sprintf("AppSec block: %s from %s (%s)", inEvt.Appsec.MatchedRules.GetName(),
		alert.Source.IP, inEvt.Parsed["remediation_cmpt_ip"])
	alert.Message = &msg
	alert.StartAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	alert.StopAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	evt.Overflow.APIAlerts = []models.Alert{alert}
	evt.Overflow.Alert = &alert

	return &evt, nil
}

func EventFromRequest(r *appsec.ParsedRequest, labels map[string]string) (types.Event, error) {
	evt := types.MakeEvent(false, types.LOG, true)
	// def needs fixing
	evt.Stage = "s00-raw"
	evt.Parsed = map[string]string{
		"source_ip":           r.ClientIP,
		"target_host":         r.Host,
		"target_uri":          r.URI,
		"method":              r.Method,
		"req_uuid":            r.Tx.ID(),
		"source":              "crowdsec-appsec",
		"remediation_cmpt_ip": r.RemoteAddrNormalized,
		// TBD:
		// http_status
		// user_agent

	}
	evt.Line = types.Line{
		Time: time.Now(),
		// should we add some info like listen addr/port/path ?
		Labels:  labels,
		Process: true,
		Module:  "appsec",
		Src:     "appsec",
		Raw:     "dummy-appsec-data", // we discard empty Line.Raw items :)
	}
	evt.Appsec = types.AppsecEvent{}

	return evt, nil
}

func LogAppsecEvent(evt *types.Event, logger *log.Entry) {
	req := evt.Parsed["target_uri"]
	if len(req) > 12 {
		req = req[:10] + ".."
	}

	if evt.Meta["appsec_interrupted"] == "true" {
		logger.WithFields(log.Fields{
			"module":     "appsec",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Infof("%s blocked on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Appsec.MatchedRules), evt.Appsec.GetRuleIDs())
	} else if evt.Parsed["outofband_interrupted"] == "true" {
		logger.WithFields(log.Fields{
			"module":     "appsec",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Infof("%s out-of-band blocking rules on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Appsec.MatchedRules), evt.Appsec.GetRuleIDs())
	} else {
		logger.WithFields(log.Fields{
			"module":     "appsec",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Debugf("%s triggered non-blocking rules on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Appsec.MatchedRules), evt.Appsec.GetRuleIDs())
	}
}

func (r *AppsecRunner) AccumulateTxToEvent(evt *types.Event, req *appsec.ParsedRequest) error {
	if evt == nil {
		// an error was already emitted, let's not spam the logs
		return nil
	}

	if !req.Tx.IsInterrupted() {
		// if the phase didn't generate an interruption, we don't have anything to add to the event
		return nil
	}
	// if one interruption was generated, event is good for processing :)
	evt.Process = true

	if evt.Meta == nil {
		evt.Meta = map[string]string{}
	}

	if evt.Parsed == nil {
		evt.Parsed = map[string]string{}
	}

	if req.IsInBand {
		evt.Meta["appsec_interrupted"] = "true"
		evt.Meta["appsec_action"] = req.Tx.Interruption().Action
		evt.Parsed["inband_interrupted"] = "true"
		evt.Parsed["inband_action"] = req.Tx.Interruption().Action
	} else {
		evt.Parsed["outofband_interrupted"] = "true"
		evt.Parsed["outofband_action"] = req.Tx.Interruption().Action
	}

	if evt.Appsec.Vars == nil {
		evt.Appsec.Vars = map[string]string{}
	}

	req.Tx.Variables().All(func(v variables.RuleVariable, col collection.Collection) bool {
		for _, variable := range col.FindAll() {
			key := variable.Variable().Name()
			if variable.Key() != "" {
				key += "." + variable.Key()
			}

			if variable.Value() == "" {
				continue
			}

			for _, collectionToKeep := range r.AppsecRuntime.CompiledVariablesTracking {
				match := collectionToKeep.MatchString(key)
				if match {
					evt.Appsec.Vars[key] = variable.Value()
					r.logger.Debugf("%s.%s = %s", variable.Variable().Name(), variable.Key(), variable.Value())
				} else {
					r.logger.Debugf("%s.%s != %s (%s) (not kept)", variable.Variable().Name(), variable.Key(), collectionToKeep, variable.Value())
				}
			}
		}

		return true
	})

	for _, rule := range req.Tx.MatchedRules() {
		if rule.Message() == "" {
			r.logger.Tracef("discarding rule %d (action: %s)", rule.Rule().ID(), rule.DisruptiveAction())
			continue
		}
		kind := "outofband"
		if req.IsInBand {
			kind = "inband"
			evt.Appsec.HasInBandMatches = true
		} else {
			evt.Appsec.HasOutBandMatches = true
		}

		var name string
		version := ""
		hash := ""
		ruleNameProm := fmt.Sprintf("%d", rule.Rule().ID())

		if details, ok := appsec.AppsecRulesDetails[rule.Rule().ID()]; ok {
			// Only set them for custom rules, not for rules written in seclang
			name = details.Name
			version = details.Version
			hash = details.Hash
			ruleNameProm = details.Name

			r.logger.Debugf("custom rule for event, setting name: %s, version: %s, hash: %s", name, version, hash)
		} else {
			name = fmt.Sprintf("native_rule:%d", rule.Rule().ID())
		}

		AppsecRuleHits.With(prometheus.Labels{"rule_name": ruleNameProm, "type": kind, "source": req.RemoteAddrNormalized, "appsec_engine": req.AppsecEngine}).Inc()

		matchedZones := make([]string, 0)

		for _, matchData := range rule.MatchedDatas() {
			zone := matchData.Variable().Name()

			varName := matchData.Key()
			if varName != "" {
				zone += "." + varName
			}

			matchedZones = append(matchedZones, zone)
		}

		corazaRule := map[string]interface{}{
			"id":            rule.Rule().ID(),
			"uri":           evt.Parsed["target_uri"],
			"rule_type":     kind,
			"method":        evt.Parsed["method"],
			"disruptive":    rule.Disruptive(),
			"tags":          rule.Rule().Tags(),
			"file":          rule.Rule().File(),
			"file_line":     rule.Rule().Line(),
			"revision":      rule.Rule().Revision(),
			"secmark":       rule.Rule().SecMark(),
			"accuracy":      rule.Rule().Accuracy(),
			"msg":           rule.Message(),
			"severity":      rule.Rule().Severity().String(),
			"name":          name,
			"hash":          hash,
			"version":       version,
			"matched_zones": matchedZones,
			"logdata":       rule.Data(),
		}
		evt.Appsec.MatchedRules = append(evt.Appsec.MatchedRules, corazaRule)
	}

	return nil
}
