package types

import (
	"encoding/json"
	"fmt"
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
	Line Line `yaml:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `yaml:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `json:"Enriched,omitempty" yaml:"Enriched,omitempty"`
	/* Overflow */
	Overflow      *SignalOccurence `yaml:"Overflow,omitempty"`
	Time          time.Time        `json:"Time,omitempty"` //parsed time
	StrTime       string           `yaml:"StrTime,omitempty"`
	MarshaledTime string           `yaml:"MarshaledTime,omitempty"`
	Process       bool             `yaml:"Process,omitempty"` //can be set to false to avoid processing line
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `json:"Meta,omitempty" yaml:"Meta,omitempty"`
}

func MarshalForHumans(evt Event) (string, error) {
	repr := make(map[string]interface{})

	repr["Whitelisted"] = evt.Whitelisted
	repr["WhiteListReason"] = evt.WhiteListReason
	repr["Stage"] = evt.Stage
	if evt.Line.Raw != "" {
		repr["Line"] = evt.Line
	}
	if len(evt.Parsed) > 0 {
		repr["Parsed"] = evt.Parsed
	}
	if len(evt.Enriched) > 0 {
		repr["Enriched"] = evt.Enriched
	}
	if len(evt.Meta) > 0 {
		repr["Meta"] = evt.Meta
	}
	if evt.Overflow.Events_count != 0 {
		repr["Overflow"] = evt.Overflow
	}
	repr["StrTime"] = evt.StrTime
	repr["Process"] = evt.Process
	output, err := json.MarshalIndent(repr, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal : %s", err)
	}
	return string(output), nil
}

func MarshalForAPI() ([]byte, error) {
	return nil, nil
}
