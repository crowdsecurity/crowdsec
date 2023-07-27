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

func LogWaapEvent(evt *types.Event) {
	/*log.WithFields(log.Fields{
		"module":     "waf",
		"source":     evt.Parsed["source_ip"],
		"target_uri": evt.Parsed["target_uri"],
	}).Infof("%s triggered %d rules [%+v]", evt.Parsed["source_ip"], len(evt.Waap), evt.Waap.GetRuleIDs())*/
	//log.Infof("%s", evt.Waap)
}

func (r *WafRunner) AccumulateTxToEvent(tx experimental.FullTransaction, kind string, evt *types.Event) error {

	//log.Infof("tx addr: %p", tx)
	if tx.IsInterrupted() {
		r.logger.Infof("interrupted() = %t", tx.IsInterrupted())
		r.logger.Infof("interrupted.action = %s", tx.Interruption().Action)
		if evt.Meta == nil {
			evt.Meta = map[string]string{}
		}
		evt.Parsed["interrupted"] = "true"
		evt.Parsed["action"] = tx.Interruption().Action

		//log.Infof("action: %s", tx.Interruption().Action)

		evt.Meta["waap_interrupted"] = "1"
		evt.Meta["waap_action"] = tx.Interruption().Action
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
			evt.Waap.Vars[key] = variable.Value()
			r.logger.Infof("%s.%s = %s", variable.Variable().Name(), variable.Key(), variable.Value())
		}
		return true
	})

	r.logger.Infof("variables addr in AccumulateTxToEvent: %p", tx.Variables())
	//log.Infof("variables: %s", spew.Sdump(tx.Variables()))
	//log.Infof("tx variables: %+v", tx.Collection(variables.TX))
	//log.Infof("TX %s", spew.Sdump(tx.MatchedRules()))
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
