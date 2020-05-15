package types

import (
	"time"
)

const (
	LOG = iota
	OVFLW
)

type Event struct {
	/* is it a log or an overflow */
	Type            int    `yaml:"Type,omitempty"`
	ExpectMode      int    `yaml:"ExpectMode,omitempty"` //how to buckets should handle event : leaky.TIMEMACHINE or leaky.LIVE
	Whitelisted     bool   `yaml:"Whitelisted,omitempty"`
	WhiteListReason string `json:"whitelist_reason,omitempty"`
	//should add whitelist reason ?
	/* the current stage of the line being parsed */
	Stage string `yaml:"Stage,omitempty"`
	/* original line (produced by acquisition) */
	Line Line `json:"-" yaml:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `json:"-" yaml:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `json:"Enriched,omitempty" yaml:"Enriched,omitempty"`
	/* Overflow */
	Overflow      SignalOccurence `yaml:"Overflow,omitempty"`
	Time          time.Time       `json:"Time,omitempty"` //parsed time `json:"-"` ``
	StrTime       string          `yaml:"StrTime,omitempty"`
	MarshaledTime string          `yaml:"MarshaledTime,omitempty"`
	Process       bool            `yaml:"Process,omitempty"` //can be set to false to avoid processing line
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `json:"Meta,omitempty" yaml:"Meta,omitempty"`
}
