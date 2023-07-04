package wafacquisition

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func TxToEvents(r waf.ParsedRequest, kind string) ([]types.Event, error) {
	evts := []types.Event{}
	if r.Tx == nil {
		return nil, fmt.Errorf("tx is nil")
	}
	for _, rule := range r.Tx.MatchedRules() {
		//log.Printf("rule %d", idx)
		if rule.Message() == "" {
			continue
		}
		evt, err := RuleMatchToEvent(rule, r.Tx, r, kind)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot convert rule match to event")
		}
		evts = append(evts, evt)
	}

	return evts, nil
}

// Transforms a coraza interruption to a crowdsec event
func RuleMatchToEvent(rule corazatypes.MatchedRule, tx corazatypes.Transaction, r waf.ParsedRequest, kind string) (types.Event, error) {
	evt := types.Event{}
	//we might want to change this based on in-band vs out-of-band ?
	evt.Type = types.LOG
	evt.ExpectMode = types.LIVE
	//def needs fixing
	evt.Stage = "s00-raw"
	evt.Process = true
	log.Infof("SOURCE IP: %+v", rule)
	//we build a big-ass object that is going to be marshaled in line.raw and unmarshaled later.
	//why ? because it's more consistent with the other data-sources etc. and it provides users with flexibility to alter our parsers
	CorazaEvent := map[string]interface{}{
		//core rule info
		"rule_type": kind,
		"rule_id":   rule.Rule().ID(),
		//"rule_action":     tx.Interruption().Action,
		"rule_disruptive": rule.Disruptive(),
		"rule_tags":       rule.Rule().Tags(),
		"rule_file":       rule.Rule().File(),
		"rule_file_line":  rule.Rule().Line(),
		"rule_revision":   rule.Rule().Revision(),
		"rule_secmark":    rule.Rule().SecMark(),
		"rule_accuracy":   rule.Rule().Accuracy(),

		//http contextual infos
		"upstream_addr": r.RemoteAddr,
		"req_uuid":      tx.ID(),
		"source_ip":     strings.Split(rule.ClientIPAddress(), ":")[0],
		"uri":           rule.URI(),
	}

	if tx.Interruption() != nil {
		CorazaEvent["rule_action"] = tx.Interruption().Action
	}
	corazaEventB, err := json.Marshal(CorazaEvent)
	if err != nil {
		return evt, fmt.Errorf("Unable to marshal coraza alert: %w", err)
	}
	evt.Line = types.Line{
		Time: time.Now(),
		//should we add some info like listen addr/port/path ?
		Labels:  map[string]string{"type": "waf"},
		Process: true,
		Module:  "waf",
		Src:     "waf",
		Raw:     string(corazaEventB),
	}

	return evt, nil
}
