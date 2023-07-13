package types

import (
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	LOG = iota
	OVFLW
)

/*
 1. If user triggered a rule that is for a CVE, that has high confidence and that is blocking, ban
 2. If user triggered 3 distinct rules with medium confidence accross 3 different requests, ban


any(evt.Waf.ByTag("CVE"), {.confidence == "high" && .action == "block"})

len(evt.Waf.ByTagRx("*CVE*").ByConfidence("high").ByAction("block")) > 1

*/

type WaapEvent []map[string]interface{}

func (w WaapEvent) ByID(id int) WaapEvent {
	waap := WaapEvent{}

	for _, rule := range w {
		if rule["id"] == id {
			waap = append(waap, rule)
		}
	}
	return waap
}

func (w WaapEvent) GetURI() string {
	for _, rule := range w {
		return rule["uri"].(string)
	}
	return ""
}

func (w WaapEvent) GetMethod() string {
	for _, rule := range w {
		return rule["method"].(string)
	}
	return ""
}

func (w WaapEvent) GetRuleIDs() []int {
	ret := make([]int, 0)
	for _, rule := range w {
		ret = append(ret, rule["id"].(int))
	}
	return ret
}

func (w WaapEvent) ByKind(kind string) WaapEvent {
	waap := WaapEvent{}
	for _, rule := range w {
		if rule["kind"] == kind {
			waap = append(waap, rule)
		}
	}
	return waap
}

func (w WaapEvent) Kinds() []string {
	ret := make([]string, 0)
	for _, rule := range w {
		exists := false
		for _, val := range ret {
			if val == rule["kind"] {
				exists = true
				break
			}
		}
		if !exists {
			ret = append(ret, rule["kind"].(string))
		}
	}
	return ret
}

func (w WaapEvent) ByTag(match string) WaapEvent {
	waap := WaapEvent{}
	for _, rule := range w {
		for _, tag := range rule["tags"].([]string) {
			if tag == match {
				waap = append(waap, rule)
				break
			}
		}
	}
	return waap
}

func (w WaapEvent) ByTagRx(rx string) WaapEvent {
	waap := WaapEvent{}
	re := regexp.MustCompile(rx)
	if re == nil {
		return waap
	}
	for _, rule := range w {
		for _, tag := range rule["tags"].([]string) {
			if re.MatchString(tag) {
				waap = append(waap, rule)
				break
			}
		}
	}
	return waap
}

func (w WaapEvent) ByDisruptiveness(is bool) WaapEvent {
	log.Infof("%s", w)
	wap := WaapEvent{}
	for _, rule := range w {
		if rule["disruptive"] == is {
			wap = append(wap, rule)
		}
	}
	log.Infof("ByDisruptiveness(%t) -> %d", is, len(wap))

	return wap
}

func (w WaapEvent) BySeverity(severity string) WaapEvent {
	wap := WaapEvent{}
	for _, rule := range w {
		if rule["severity"] == severity {
			wap = append(wap, rule)
		}
	}
	log.Infof("BySeverity(%t) -> %d", severity, len(wap))
	return wap
}

// Event is the structure representing a runtime event (log or overflow)
type Event struct {
	/* is it a log or an overflow */
	Type            int    `yaml:"Type,omitempty" json:"Type,omitempty"`             //Can be types.LOG (0) or types.OVFLOW (1)
	ExpectMode      int    `yaml:"ExpectMode,omitempty" json:"ExpectMode,omitempty"` //how to buckets should handle event : types.TIMEMACHINE or types.LIVE
	Whitelisted     bool   `yaml:"Whitelisted,omitempty" json:"Whitelisted,omitempty"`
	WhitelistReason string `yaml:"WhitelistReason,omitempty" json:"whitelist_reason,omitempty"`
	//should add whitelist reason ?
	/* the current stage of the line being parsed */
	Stage string `yaml:"Stage,omitempty" json:"Stage,omitempty"`
	/* original line (produced by acquisition) */
	Line Line `yaml:"Line,omitempty" json:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `yaml:"Parsed,omitempty" json:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `yaml:"Enriched,omitempty" json:"Enriched,omitempty"`
	/* output of Unmarshal */
	Unmarshaled map[string]interface{} `yaml:"Unmarshaled,omitempty" json:"Unmarshaled,omitempty"`
	/* Overflow */
	Overflow      RuntimeAlert `yaml:"Overflow,omitempty" json:"Alert,omitempty"`
	Time          time.Time    `yaml:"Time,omitempty" json:"Time,omitempty"` //parsed time `json:"-"` ``
	StrTime       string       `yaml:"StrTime,omitempty" json:"StrTime,omitempty"`
	StrTimeFormat string       `yaml:"StrTimeFormat,omitempty" json:"StrTimeFormat,omitempty"`
	MarshaledTime string       `yaml:"MarshaledTime,omitempty" json:"MarshaledTime,omitempty"`
	Process       bool         `yaml:"Process,omitempty" json:"Process,omitempty"` //can be set to false to avoid processing line
	Waap          WaapEvent    `yaml:"Waap,omitempty" json:"Waap,omitempty"`
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `yaml:"Meta,omitempty" json:"Meta,omitempty"`
}

func (e *Event) GetType() string {
	if e.Type == OVFLW {
		return "overflow"
	} else if e.Type == LOG {
		return "log"
	} else {
		log.Warningf("unknown event type for %+v", e)
		return "unknown"
	}
}

func (e *Event) GetMeta(key string) string {
	if e.Type == OVFLW {
		for _, alert := range e.Overflow.APIAlerts {
			for _, event := range alert.Events {
				if event.GetMeta(key) != "" {
					return event.GetMeta(key)
				}
			}
		}
	} else if e.Type == LOG {
		for k, v := range e.Meta {
			if k == key {
				return v
			}
		}
	}
	return ""
}

// Move in leakybuckets
const (
	Undefined = ""
	Ip        = "Ip"
	Range     = "Range"
	Filter    = "Filter"
	Country   = "Country"
	AS        = "AS"
)

// Move in leakybuckets
type ScopeType struct {
	Scope         string `yaml:"type"`
	Filter        string `yaml:"expression"`
	RunTimeFilter *vm.Program
}

type RuntimeAlert struct {
	Mapkey      string                   `yaml:"MapKey,omitempty" json:"MapKey,omitempty"`
	BucketId    string                   `yaml:"BucketId,omitempty" json:"BucketId,omitempty"`
	Whitelisted bool                     `yaml:"Whitelisted,omitempty" json:"Whitelisted,omitempty"`
	Reprocess   bool                     `yaml:"Reprocess,omitempty" json:"Reprocess,omitempty"`
	Sources     map[string]models.Source `yaml:"Sources,omitempty" json:"Sources,omitempty"`
	Alert       *models.Alert            `yaml:"Alert,omitempty" json:"Alert,omitempty"` //this one is a pointer to APIAlerts[0] for convenience.
	//APIAlerts will be populated at the end when there is more than one source
	APIAlerts []models.Alert `yaml:"APIAlerts,omitempty" json:"APIAlerts,omitempty"`
}

func (r RuntimeAlert) GetSources() []string {
	ret := make([]string, 0)
	for key := range r.Sources {
		ret = append(ret, key)
	}
	return ret
}
