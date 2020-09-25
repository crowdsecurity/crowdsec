package types

import (
	"time"

	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	LOG = iota
	OVFLW
)

type Event struct {
	/* is it a log or an overflow */
	Type            int    `yaml:"Type,omitempty" json:"Type,omitempty"`
	ExpectMode      int    `yaml:"ExpectMode,omitempty" json:"ExpectMode,omitempty"` //how to buckets should handle event : leaky.TIMEMACHINE or leaky.LIVE
	Whitelisted     bool   `yaml:"Whitelisted,omitempty" json:"Whitelisted,omitempty"`
	WhiteListReason string `yaml:"whitelist_reason,omitempty" json:"whitelist_reason,omitempty"`
	//should add whitelist reason ?
	/* the current stage of the line being parsed */
	Stage string `yaml:"Stage,omitempty" json:"Stage,omitempty"`
	/* original line (produced by acquisition) */
	Line Line `yaml:"Line,omitempty" json:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `yaml:"Parsed,omitempty" json:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `yaml:"Enriched,omitempty" json:"Enriched,omitempty"`
	/* Overflow */
	Overflow      RuntimeAlert `yaml:"Alert,omitempty" json:"Alert,omitempty"`
	Time          time.Time    `yaml:"Time,omitempty" json:"Time,omitempty"` //parsed time `json:"-"` ``
	StrTime       string       `yaml:"StrTime,omitempty" json:"StrTime,omitempty"`
	MarshaledTime string       `yaml:"MarshaledTime,omitempty" json:"MarshaledTime,omitempty"`
	Process       bool         `yaml:"Process,omitempty" json:"Process,omitempty"` //can be set to false to avoid processing line
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `yaml:"Meta,omitempty" json:"Meta,omitempty"`
}

//Move in leakybuckets
const (
	Undefined = ""
	Ip        = "Ip"
	Range     = "Range"
	Filter    = "Filter"
)

//Move in leakybuckets
type ScopeType struct {
	Scope         string `yaml:"scope_type"`
	Filter        string `yaml:"filter"`
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

func (r *RuntimeAlert) GetSingleSource() (string, string) {
	srcScope := ""
	srcVal := ""
	for k, v := range r.Sources {
		srcScope = *v.Scope
		srcVal = k
		break
	}
	return srcScope, srcVal
}
