package wafacquisition

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/coraza/v3/collection"
	"github.com/crowdsecurity/coraza/v3/experimental"
	"github.com/crowdsecurity/coraza/v3/types/variables"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

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

/*
 how to configure variables to be kept:
  1) full collection : tx.*
  2) subvariables : tx.a*

*/

// func LogWaapEvent(evt *types.Event) error {

// 	return nil
// }

func AccumulateTxToEvent(logger log.Entry, tx experimental.FullTransaction, kind string, evt *types.Event, wr *waf.WaapRuntimeConfig) error {

	if tx.IsInterrupted() {
		if evt.Meta == nil {
			evt.Meta = map[string]string{}
		}
		if kind == InBand {
			evt.Meta["waap_interrupted"] = "true"
			evt.Meta["waap_action"] = tx.Interruption().Action
			evt.Parsed["inband_interrupted"] = "true"
			evt.Parsed["inband_action"] = tx.Interruption().Action
		} else {
			evt.Parsed["outofband_interrupted"] = "true"
			evt.Parsed["outofband_action"] = tx.Interruption().Action
		}
	}

	if evt.Waap.Vars == nil {
		evt.Waap.Vars = map[string]string{}
	}

	tx.Variables().All(func(v variables.RuleVariable, col collection.Collection) bool {
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
			for _, collectionToKeep := range wr.CompiledVariablesTracking {
				match := collectionToKeep.MatchString(key)
				if match {
					evt.Waap.Vars[key] = variable.Value()
					logger.Debugf("%s.%s = %s", variable.Variable().Name(), variable.Key(), variable.Value())
				} else {
					logger.Debugf("%s.%s != %s (%s) (not kept)", variable.Variable().Name(), variable.Key(), collectionToKeep, variable.Value())
				}
			}
		}
		return true
	})

	for _, rule := range tx.MatchedRules() {
		if rule.Message() == "" {
			continue
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
