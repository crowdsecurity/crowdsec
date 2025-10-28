package types

import (
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const (
	APPSEC = pipeline.APPSEC
	LIVE = pipeline.LIVE
	LOG = pipeline.LOG
	OVFLW = pipeline.OVFLW
	TIMEMACHINE = pipeline.TIMEMACHINE
)

type (
	Event = pipeline.Event
	Line = pipeline.Line
	AppsecEvent = pipeline.AppsecEvent
	MatchedRule = pipeline.MatchedRule
	Queue = pipeline.Queue
	RuntimeAlert = pipeline.RuntimeAlert
	MatchedRules = pipeline.MatchedRules
)

var (
	MakeEvent = pipeline.MakeEvent
	NewMatchedRule = pipeline.NewMatchedRule
	NewQueue = pipeline.NewQueue
)
