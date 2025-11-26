package cloudwatchacquisition

import (
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

// Source is the runtime instance keeping track of N streams within 1 cloudwatch group
type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration
	// runtime stuff
	logger           *log.Entry
	t                *tomb.Tomb
	cwClient         *cloudwatchlogs.Client
	monitoredStreams []*LogStreamTailConfig
	streamIndexes    map[string]string
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return "cloudwatch"
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
