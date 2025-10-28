package types

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/fsutil"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
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
	DataSource = enrichment.DataProvider
	Queue = pipeline.Queue
	RuntimeAlert = pipeline.RuntimeAlert
	MatchedRules = pipeline.MatchedRules
)

var (
	IsNetworkFS = fsutil.IsNetworkFS
	MakeEvent = pipeline.MakeEvent
	ConfigureLogger = logging.ConfigureLogger
	NewMatchedRule = pipeline.NewMatchedRule
	NewQueue = pipeline.NewQueue
	SetDefaultLoggerConfig = logging.SetDefaultLoggerConfig
)

func UtcNow() time.Time {
	return time.Now().UTC()
}
