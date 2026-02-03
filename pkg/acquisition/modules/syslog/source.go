package syslogacquisition

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (*Source) GetName() string {
	return ModuleName
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (s *Source) Dump() any {
	return s
}

func (*Source) CanRun() error {
	return nil
}
