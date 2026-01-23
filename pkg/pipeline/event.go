package pipeline

import (
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	LOG = iota
	OVFLW
	APPSEC
)

// Event is the structure representing a runtime event (log or overflow)
type Event struct {
	/* is it a log or an overflow */
	Type            int    `json:"Type,omitempty"             yaml:"Type,omitempty"`       // Can be types.LOG (0) or types.OVFLOW (1)
	ExpectMode      int    `json:"ExpectMode,omitempty"       yaml:"ExpectMode,omitempty"` // how to buckets should handle event : types.TIMEMACHINE or types.LIVE
	Whitelisted     bool   `json:"Whitelisted,omitempty"      yaml:"Whitelisted,omitempty"`
	WhitelistReason string `json:"whitelist_reason,omitempty" yaml:"WhitelistReason,omitempty"`
	// should add whitelist reason ?
	/* the current stage of the line being parsed */
	Stage string `json:"Stage,omitempty" yaml:"Stage,omitempty"`
	/* original line (produced by acquisition) */
	Line Line `json:"Line,omitempty" yaml:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `json:"Parsed,omitempty" yaml:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `json:"Enriched,omitempty" yaml:"Enriched,omitempty"`
	/* output of Unmarshal */
	Unmarshaled map[string]any `json:"Unmarshaled,omitempty" yaml:"Unmarshaled,omitempty"`
	/* Overflow */
	Overflow      RuntimeAlert `json:"Alert,omitempty"         yaml:"Overflow,omitempty"`
	Time          time.Time    `json:"Time,omitempty"          yaml:"Time,omitempty"` // parsed time `json:"-"` ``
	StrTime       string       `json:"StrTime,omitempty"       yaml:"StrTime,omitempty"`
	StrTimeFormat string       `json:"StrTimeFormat,omitempty" yaml:"StrTimeFormat,omitempty"`
	MarshaledTime string       `json:"MarshaledTime,omitempty" yaml:"MarshaledTime,omitempty"`
	Process       bool         `json:"Process,omitempty"       yaml:"Process,omitempty"` // can be set to false to avoid processing line
	Appsec        AppsecEvent  `json:"Appsec,omitempty"        yaml:"Appsec,omitempty"`
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `json:"Meta,omitempty" yaml:"Meta,omitempty"`
}

func MakeEvent(timeMachine bool, evtType int, process bool) Event {
	evt := Event{
		Parsed:      make(map[string]string),
		Meta:        make(map[string]string),
		Unmarshaled: make(map[string]any),
		Enriched:    make(map[string]string),
		ExpectMode:  LIVE,
		Process:     process,
		Type:        evtType,
	}
	if timeMachine {
		evt.ExpectMode = TIMEMACHINE
	}

	return evt
}

func (e *Event) SetMeta(key string, value string) bool {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}

	e.Meta[key] = value

	return true
}

func (e *Event) SetParsed(key string, value string) bool {
	if e.Parsed == nil {
		e.Parsed = make(map[string]string)
	}

	e.Parsed[key] = value

	return true
}

func (e *Event) GetType() string {
	switch e.Type {
	case OVFLW:
		return "overflow"
	case LOG:
		return "log"
	default:
		log.Warningf("unknown event type for %+v", e)
		return "unknown"
	}
}

func (e *Event) GetMeta(key string) string {
	if e.Type == OVFLW {
		alerts := e.Overflow.APIAlerts
		for idx := range alerts {
			for _, event := range alerts[idx].Events {
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

func (e *Event) ParseIPSources() []netip.Addr {
	var srcs []netip.Addr

	switch e.Type {
	case LOG:
		if val, ok := e.Meta["source_ip"]; ok {
			if addr, err := netip.ParseAddr(val); err == nil {
				srcs = append(srcs, addr)
			} else {
				log.Errorf("failed to parse source_ip %s: %v", val, err)
			}
		}
	case OVFLW:
		for k := range e.Overflow.Sources {
			if addr, err := netip.ParseAddr(k); err == nil {
				srcs = append(srcs, addr)
			} else {
				log.Errorf("failed to parse source %s: %v", k, err)
			}
		}
	}

	return srcs
}

type RuntimeAlert struct {
	Mapkey      string                   `json:"MapKey,omitempty"      yaml:"MapKey,omitempty"`
	BucketId    string                   `json:"BucketId,omitempty"    yaml:"BucketId,omitempty"`
	Whitelisted bool                     `json:"Whitelisted,omitempty" yaml:"Whitelisted,omitempty"`
	Reprocess   bool                     `json:"Reprocess,omitempty"   yaml:"Reprocess,omitempty"`
	Sources     map[string]models.Source `json:"Sources,omitempty"     yaml:"Sources,omitempty"`
	Alert       *models.Alert            `json:"Alert,omitempty"       yaml:"Alert,omitempty"` // this one is a pointer to APIAlerts[0] for convenience.
	// APIAlerts will be populated at the end when there is more than one source
	APIAlerts []models.Alert `json:"APIAlerts,omitempty" yaml:"APIAlerts,omitempty"`
}

func (r RuntimeAlert) GetSources() []string {
	ret := make([]string, 0)
	for key := range r.Sources {
		ret = append(ret, key)
	}

	return ret
}
