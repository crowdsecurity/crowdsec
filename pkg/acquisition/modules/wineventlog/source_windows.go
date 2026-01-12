package wineventlogacquisition

import (
	"errors"
	"runtime"

	"github.com/google/winops/winlog"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       Configuration
	logger       *log.Entry
	evtConfig    *winlog.SubscribeConfig
	query        string
	name         string
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (*Source) GetName() string {
	return "wineventlog"
}

func (*Source) CanRun() error {
	if runtime.GOOS != "windows" {
		return errors.New("windows event log acquisition is only supported on Windows")
	}
	return nil
}

func (s *Source) Dump() interface{} {
	return s
}
