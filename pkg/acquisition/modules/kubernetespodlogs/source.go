package kubernetespodlogs

import (
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration

	logger *log.Entry
	t      tomb.Tomb
}

func (*Source) GetName() string {
	return ModuleName
}

func (d *Source) GetMode() string {
	return d.Config.Mode
}

func (*Source) CanRun() error {
	return nil
}

func (d *Source) GetUuid() string {
	return d.Config.UniqueId
}
