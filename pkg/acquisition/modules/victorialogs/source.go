package victorialogs

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs/internal/vlclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration

	Client *vlclient.VLClient

	logger *log.Entry
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return "victorialogs"
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (s *Source) Dump() any {
	return s
}
