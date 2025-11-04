package journalctlacquisition

import (
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
	src          string	// specific source name (i.e. journalctl-<filters>)
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (*Source) GetName() string {
	return "journalctl"
}

func (*Source) CanRun() error {
	// TODO: add a more precise check on version or something ?
	_, err := exec.LookPath(journalctlCmd)
	return err
}

func (s *Source) Dump() any {
	return s
}
