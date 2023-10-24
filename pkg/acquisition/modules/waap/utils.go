package wafacquisition

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/coraza/v3/collection"
	"github.com/crowdsecurity/coraza/v3/types/variables"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

func WaapEventGeneration(inEvt types.Event) (types.Event, error) {
	evt := types.Event{}
	evt.Type = types.WAAP
	evt.Process = true
	source := models.Source{
		Value: ptr.Of(inEvt.Parsed["source_ip"]),
		IP:    inEvt.Parsed["source_ip"],
		Scope: ptr.Of(types.Ip),
	}

	evt.Overflow.Sources = make(map[string]models.Source)
	evt.Overflow.Sources["ip"] = source

	alert := models.Alert{}
	alert.Capacity = ptr.Of(int32(1))
	alert.Events = make([]*models.Event, 0) //@tko -> URI, method, UA, param name
	alert.Meta = make(models.Meta, 0)       //@tko -> URI, method, UA, param name
	alert.EventsCount = ptr.Of(int32(1))
	alert.Labels = []string{"waf"} //don't know what to do about this
	alert.Leakspeed = ptr.Of("")
	msg := fmt.Sprintf("WAF alert: %s", inEvt.Waap.MatchedRules.GetName())
	alert.Message = &msg
	alert.Scenario = ptr.Of(inEvt.Waap.MatchedRules.GetName())           // @sbl : should we be able to do inEvt.Waap.MatchedRules.GetHash()
	alert.ScenarioHash = ptr.Of(inEvt.Waap.MatchedRules.GetHash())       // @sbl : should we be able to do inEvt.Waap.MatchedRules.GetHash()
	alert.ScenarioVersion = ptr.Of(inEvt.Waap.MatchedRules.GetVersion()) // @sbl : should we be able to do inEvt.Waap.MatchedRules.GetVersion()
	alert.Simulated = ptr.Of(false)
	alert.Source = &source
	alert.StartAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	alert.StopAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))

	evt.Overflow.APIAlerts = []models.Alert{alert}
	evt.Overflow.Alert = &alert
	return evt, nil
}

func EventFromRequest(r waf.ParsedRequest) (types.Event, error) {
	evt := types.Event{}
	//we might want to change this based on in-band vs out-of-band ?
	evt.Type = types.LOG
	evt.ExpectMode = types.LIVE
	//def needs fixing
	evt.Stage = "s00-raw"
	evt.Process = true
	evt.Parsed = map[string]string{
		"source_ip":   r.ClientIP,
		"target_host": r.Host,
		"target_uri":  r.URI,
		"method":      r.Method,
		"req_uuid":    r.Tx.ID(),
		"source":      "coraza",

		//TBD:
		//http_status
		//user_agent

	}
	evt.Line = types.Line{
		Time: time.Now(),
		//should we add some info like listen addr/port/path ?
		Labels:  map[string]string{"type": "coraza-waf"},
		Process: true,
		Module:  "waf",
		Src:     "waf",
		Raw:     "dummy-waf-data", //we discard empty Line.Raw items :)
	}
	evt.Waap = types.WaapEvent{}

	return evt, nil
}

func LogWaapEvent(evt *types.Event, logger *log.Entry) {
	req := evt.Parsed["target_uri"]
	if len(req) > 12 {
		req = req[:10] + ".."
	}

	if evt.Meta["waap_interrupted"] == "true" {
		logger.WithFields(log.Fields{
			"module":     "waf",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Infof("%s blocked on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Waap.MatchedRules), evt.Waap.GetRuleIDs())
	} else if evt.Parsed["outofband_interrupted"] == "true" {
		logger.WithFields(log.Fields{
			"module":     "waf",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Infof("%s out-of-band blocking rules on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Waap.MatchedRules), evt.Waap.GetRuleIDs())
	} else {
		logger.WithFields(log.Fields{
			"module":     "waf",
			"source":     evt.Parsed["source_ip"],
			"target_uri": req,
		}).Debugf("%s triggerd non-blocking rules on %s (%d rules) [%v]", evt.Parsed["source_ip"], req, len(evt.Waap.MatchedRules), evt.Waap.GetRuleIDs())
	}

}

func (r *WaapRunner) AccumulateTxToEvent(evt *types.Event, req waf.ParsedRequest) error {

	if evt == nil {
		//an error was already emitted, let's not spam the logs
		return nil
	}
	if req.Tx.IsInterrupted() {
		if evt.Meta == nil {
			evt.Meta = map[string]string{}
		}
		if req.IsInBand {
			evt.Meta["waap_interrupted"] = "true"
			evt.Meta["waap_action"] = req.Tx.Interruption().Action
			evt.Parsed["inband_interrupted"] = "true"
			evt.Parsed["inband_action"] = req.Tx.Interruption().Action
		} else {
			evt.Parsed["outofband_interrupted"] = "true"
			evt.Parsed["outofband_action"] = req.Tx.Interruption().Action
		}
	}

	if evt.Waap.Vars == nil {
		evt.Waap.Vars = map[string]string{}
	}

	req.Tx.Variables().All(func(v variables.RuleVariable, col collection.Collection) bool {
		for _, variable := range col.FindAll() {
			key := ""
			if variable.Key() == "" {
				key = variable.Variable().Name()
			} else {
				key = variable.Variable().Name() + "." + variable.Key()
			}
			if variable.Value() == "" {
				continue
			}
			for _, collectionToKeep := range r.WaapRuntime.CompiledVariablesTracking {
				match := collectionToKeep.MatchString(key)
				if match {
					evt.Waap.Vars[key] = variable.Value()
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
			r.logger.Tracef("discarding rule %d", rule.Rule().ID())
			continue
		}
		kind := "outofband"
		if req.IsInBand {
			kind = "inband"
		}
		WafRuleHits.With(prometheus.Labels{"rule_id": fmt.Sprintf("%d", rule.Rule().ID()), "type": kind}).Inc()

		corazaRule := map[string]interface{}{
			"id":         rule.Rule().ID(),
			"uri":        evt.Parsed["uri"],
			"rule_type":  kind,
			"method":     evt.Parsed["method"],
			"disruptive": rule.Disruptive(),
			"tags":       rule.Rule().Tags(),
			"file":       rule.Rule().File(),
			"file_line":  rule.Rule().Line(),
			"revision":   rule.Rule().Revision(),
			"secmark":    rule.Rule().SecMark(),
			"accuracy":   rule.Rule().Accuracy(),
			"msg":        rule.Message(),
			"severity":   rule.Rule().Severity().String(),
		}
		evt.Waap.MatchedRules = append(evt.Waap.MatchedRules, corazaRule)
	}

	return nil

}
