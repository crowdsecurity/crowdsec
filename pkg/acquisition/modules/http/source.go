package httpacquisition

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration
	logger       *log.Entry
	Server       *http.Server
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return "http"
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
