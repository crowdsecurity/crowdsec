package journalctlacquisition

import (
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type JournalCtlSource struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
	src          string
}

func (j *JournalCtlSource) GetUuid() string {
	return j.config.UniqueId
}

func (j *JournalCtlSource) GetMode() string {
	return j.config.Mode
}

func (*JournalCtlSource) GetName() string {
	return "journalctl"
}

func (*JournalCtlSource) CanRun() error {
	// TODO: add a more precise check on version or something ?
	_, err := exec.LookPath(journalctlCmd)
	return err
}

func (j *JournalCtlSource) Dump() any {
	return j
}
