package kubernetesauditacquisition

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
	mux          *http.ServeMux
	server       *http.Server
	outChan      chan pipeline.Event
	addr         string
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (*Source) GetName() string {
	return ModuleName
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
