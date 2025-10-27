package types

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/fsutil"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const (
	APPSEC = flow.APPSEC
	LIVE = flow.LIVE
	LOG = flow.LOG
	OVFLW = flow.OVFLW
	TIMEMACHINE = flow.TIMEMACHINE
)

type (
	Event = flow.Event
	Line = flow.Line
	AppsecEvent = flow.AppsecEvent
	MatchedRule = flow.MatchedRule
	DataSource = enrichment.DataProvider
	Queue = flow.Queue
	RuntimeAlert = flow.RuntimeAlert
	MatchedRules = flow.MatchedRules
)

var (
	IsNetworkFS = fsutil.IsNetworkFS
	MakeEvent = flow.MakeEvent
	ConfigureLogger = logging.ConfigureLogger
	NewMatchedRule = flow.NewMatchedRule
	NewQueue = flow.NewQueue
	SetDefaultLoggerConfig = logging.SetDefaultLoggerConfig
)

func UtcNow() time.Time {
	return time.Now().UTC()
}
