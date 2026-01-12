package loki

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki/internal/lokiclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration

	Client *lokiclient.LokiClient

	logger        *log.Entry
	lokiWebsocket string
}

func (l *Source) GetMode() string {
	return l.Config.Mode
}

func (*Source) GetName() string {
	return "loki"
}

func (*Source) CanRun() error {
	return nil
}

func (l *Source) GetUuid() string {
	return l.Config.UniqueId
}

func (l *Source) Dump() any {
	return l
}
