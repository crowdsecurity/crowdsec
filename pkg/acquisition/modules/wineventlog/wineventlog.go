//go:build !windows

package wineventlogacquisition

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type WinEventLogSource struct{}

func (w *WinEventLogSource) GetUuid() string {
	return ""
}

func (w *WinEventLogSource) UnmarshalConfig(yamlConfig []byte) error {
	return nil
}

func (w *WinEventLogSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	return nil
}

func (w *WinEventLogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	return nil
}

func (w *WinEventLogSource) GetMode() string {
	return ""
}

func (w *WinEventLogSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (w *WinEventLogSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (w *WinEventLogSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (w *WinEventLogSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (w *WinEventLogSource) GetName() string {
	return "wineventlog"
}

func (w *WinEventLogSource) CanRun() error {
	return errors.New("windows event log acquisition is only supported on Windows")
}

func (w *WinEventLogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (w *WinEventLogSource) Dump() interface{} {
	return w
}
