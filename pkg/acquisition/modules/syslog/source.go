package syslogacquisition

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/server"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
	server       *syslogserver.SyslogServer
	serverTomb   *tomb.Tomb
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (*Source) GetName() string {
	return "syslog"
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
