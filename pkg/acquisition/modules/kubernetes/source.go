package kubernetes

import (
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration

	client *kubernetes.Clientset
	logger *log.Entry
}

func (*Source) GetName() string {
	return ModuleName
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}
