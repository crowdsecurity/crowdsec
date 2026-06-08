package kubernetes

import (
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration

	client *kubernetes.Clientset
	mu     sync.Mutex
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
