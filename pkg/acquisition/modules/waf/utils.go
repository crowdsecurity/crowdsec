package wafacquisition

import (
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/experimental"
	types "github.com/crowdsecurity/crowdsec/pkg/types"
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
	}
	evt.Line = types.Line{
		Time: time.Now(),
		//should we add some info like listen addr/port/path ?
		Labels:  map[string]string{"type": "waf"},
		Process: true,
		Module:  "waf",
		Src:     "waf",
	}
	evt.Unmarshaled = map[string]interface{}{}

	return evt, nil
}

type CorazaRuleMatch struct {
	ID             int
	Message        string
	RuleFile       string
	RuleLine       int
	RuleTags       []string
	RuleSecMark    int
	RuleRevision   int
	RuleAccuracy   int
	RuleType       string
	RuleAction     string
	RuleDisruptive bool
}

func LogWaapEvent(evt *types.Event) {
	log.WithFields(log.Fields{
		"module":     "waf",
		"source":     evt.Parsed["source_ip"],
		"target_uri": evt.Parsed["target_uri"],
	}).Infof("%s triggered %d rule", evt.Parsed["source_ip"], len(evt.Unmarshaled["coraza_rules"].([]map[string]interface{})))
}

func AccumulateTxToEvent(tx experimental.FullTransaction, kind string, evt *types.Event) error {
	for _, rule := range tx.MatchedRules() {
		if rule.Message() == "" {
			continue
		}
		WafRuleHits.With(prometheus.Labels{"rule_id": fmt.Sprintf("%d", rule.Rule().ID()), "type": kind}).Inc()
		if _, ok := evt.Unmarshaled["coraza_rules"]; !ok {
			evt.Unmarshaled["coraza_rules"] = []map[string]interface{}{}
		}
		corazaRule := map[string]interface{}{
			"id":         rule.Rule().ID(),
			"rule_type":  kind,
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
		evt.Unmarshaled["coraza_rules"] = append(evt.Unmarshaled["coraza_rules"].([]map[string]interface{}), corazaRule)
	}

	return nil
}
