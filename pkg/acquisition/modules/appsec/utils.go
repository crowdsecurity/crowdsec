package appsecacquisition

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types/variables"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// If we have a match in one of those zones, set the `internal` flag of the MatchedRule
// To prevent them from being sent in the context (as they are almost never relevant to the user)
// They are still present in the metas of the alert itself for reference
// This is rather CRS-specific, but we don't expect to write custom rules as complex as the CRS
var excludedMatchCollections = []string{
	"REQBODY_PROCESSOR", // Matched when enabling the body processor
	"UNKNOWN",           // Matched by the anomaly score rule
	"TX",                // Score has been exceeded
}

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

func formatCRSMatch(vars map[string]string, hasInBandMatches bool, hasOutBandMatches bool) string {
	msg := "anomaly score "
	switch {
	case hasInBandMatches:
		msg += "block: "
	case hasOutBandMatches:
		msg += "out-of-band: "
	}
	for _, var_name := range appsec.CRSAnomalyScores {
		if val, ok := vars[var_name]; ok && val != "0" {
			msg += fmt.Sprintf("%s: %s, ", strings.Replace(strings.Replace(var_name, "TX.", "", 1), "_score", "", 1), val)
		}
	}
	return msg
}

func AppsecEventGeneration(inEvt types.Event, request *http.Request) (*types.Event, error) {
	// if the request didn't trigger inband rules or out-of-band rules, we don't want to generate an event to LAPI/CAPI
	if !inEvt.Appsec.HasInBandMatches && !inEvt.Appsec.HasOutBandMatches {
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
	alert.Events = make([]*models.Event, len(evt.Appsec.MatchedRules))

	now := time.Now().UTC().Format(time.RFC3339)

	// Create one event (in the overflow) per matched rule
	for _, rule := range inEvt.Appsec.MatchedRules {
		event := models.Event{}
		meta := models.Meta{}

		if rule_name, ok := rule["name"].(string); ok {
			meta = append(meta, &models.MetaItems0{
				Key:   "rule_name",
				Value: rule_name,
			})
		}
		if msg, ok := rule["msg"].(string); ok {
			meta = append(meta, &models.MetaItems0{
				Key:   "message",
				Value: msg,
			})
		}
		if uri, ok := rule["uri"].(string); ok {
			meta = append(meta, &models.MetaItems0{
				Key:   "uri",
				Value: uri,
			})
		}
		if matchedZones, ok := rule["matched_zones"].([]string); ok {
			meta = append(meta, &models.MetaItems0{
				Key:   "matched_zones",
				Value: strings.Join(matchedZones, ","),
			})
		}
		if logdata, ok := rule["logdata"].(string); ok {
			meta = append(meta, &models.MetaItems0{
				Key:   "data",
				Value: logdata,
			})
		}

		event.Meta = meta
		event.Timestamp = &now
		alert.Events = append(alert.Events, &event)
	}

	metas, errors := alertcontext.AppsecEventToContext(inEvt.Appsec, request)
	if len(errors) > 0 {
		for _, err := range errors {
			log.Errorf("failed to generate appsec context: %s", err)
		}
	}

	alert.Meta = metas

	alert.EventsCount = ptr.Of(int32(len(alert.Events)))
	alert.Leakspeed = ptr.Of("")

	var scenarioName string

	// If multiple matches:
	// Get the list of rules with highest severity
	// Choose the name from those:
	// Priority to our custom rules
	// Then CRS scoring
	// Then log message
	// Then native_rule:ID
	sev := inEvt.Appsec.GetHighestSeverity().String()

	sevRules := inEvt.Appsec.BySeverity(sev)

	for _, rule := range sevRules {
		name, ok := rule["name"].(string)
		if !ok {
			continue
		}
		// Own custom format, just get the name
		if !strings.HasPrefix(name, "native_rule:") {
			scenarioName = name
			break
		}
	}

	// This is a modsec rule match
	if scenarioName == "" {
		// If from CRS (TX scores are set), use that as the name
		// If from a custom rule, use the log message from the 1st highest severity rule
		if _, ok := inEvt.Appsec.Vars["TX.anomaly_score"]; ok {
			scenarioName = formatCRSMatch(inEvt.Appsec.Vars, inEvt.Appsec.HasInBandMatches, inEvt.Appsec.HasOutBandMatches)
		} else {
			scenarioName, ok = sevRules[0]["msg"].(string)
			//Not sure if this can happen
			//Default to native_rule:XXX if msg is empty
			if scenarioName == "" || !ok {
				scenarioName = inEvt.Appsec.GetName()
			}
		}
	}

	alert.Scenario = ptr.Of(scenarioName)
	alert.ScenarioHash = ptr.Of(inEvt.Appsec.GetHash())
	alert.ScenarioVersion = ptr.Of(inEvt.Appsec.GetVersion())
	alert.Simulated = ptr.Of(false)
	alert.Source = &source

	msg := ""

	switch {
	case inEvt.Appsec.HasInBandMatches:
		msg = "WAF block: "
	case inEvt.Appsec.HasOutBandMatches:
		msg = "WAF out-of-band match: "
	}

	msg += fmt.Sprintf("%s from %s (%s)", scenarioName,
		alert.Source.IP, inEvt.Parsed["remediation_cmpt_ip"])
	alert.Message = &msg
	alert.StartAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	alert.StopAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	evt.Overflow.APIAlerts = []models.Alert{alert}
	evt.Overflow.Alert = &alert

	return &evt, nil
}

// Check if all the rule matched zones are part of the excluded zones
func containsAll(excludedZones []string, matchedZones []string) bool {
	if len(matchedZones) == 0 {
		return false
	}
	supersetMap := make(map[string]struct{}, len(excludedZones))
	for _, item := range excludedZones {
		supersetMap[item] = struct{}{}
	}

	for _, item := range matchedZones {
		if _, ok := supersetMap[item]; !ok {
			return false
		}
	}
	return true
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
			r.logger.Tracef("variable: %s.%s = %s\n", variable.Variable().Name(), variable.Key(), variable.Value())
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
		// Drop the rule if it has no message (it's likely a CRS setup rule)
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

		metrics.AppsecRuleHits.With(prometheus.Labels{"rule_name": ruleNameProm, "type": kind, "source": req.RemoteAddrNormalized, "appsec_engine": req.AppsecEngine}).Inc()

		matchedZones := make([]string, 0)
		matchedCollections := make([]string, 0)

		// Get matched zones
		internalRule := false
		for _, matchData := range rule.MatchedDatas() {
			zone := matchData.Variable().Name()
			matchedCollections = append(matchedCollections, zone)
			varName := matchData.Key()
			if varName != "" {
				zone += "." + varName
			}
			matchedZones = append(matchedZones, zone)
		}

		if containsAll(excludedMatchCollections, matchedCollections) {
			internalRule = true
			r.logger.Debugf("ignoring rule %d match on zone %+v", rule.Rule().ID(), matchedZones)
		}

		corazaRule := map[string]any{
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
			"severity_int":  rule.Rule().Severity().Int(),
			"name":          name,
			"hash":          hash,
			"version":       version,
			"matched_zones": matchedZones,
			"logdata":       rule.Data(),
		}
		if internalRule {
			corazaRule["internal"] = true
		}

		evt.Appsec.MatchedRules = append(evt.Appsec.MatchedRules, corazaRule)
	}

	return nil
}
