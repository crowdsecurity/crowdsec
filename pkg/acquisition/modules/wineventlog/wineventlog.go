package wineventlogacquisition

import (
	"errors"
	"runtime"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"gopkg.in/tomb.v2"
)

type WinEventLogConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type WinEventLogSource struct {
	config WinEventLogConfiguration
}

var (
	wevtapi      = windows.NewLazySystemDLL("wevtapi.dll")
	openEventLog = wevtapi.NewProc("OpenEventLog")
)

func (w *WinEventLogSource) Configure(Config []byte, logger *log.Entry) error {
	openEventLog.Call(0)
	return nil
}

func (w *WinEventLogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	return nil
}

func (w *WinEventLogSource) GetMode() string {
	return w.config.Mode
}

func (w *WinEventLogSource) SupportedModes() []string {
	return []string{""}
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
	if runtime.GOOS != "windows" {
		return errors.New("windows event log acquisition is only supported on Windows")
	}
	return nil
}

func (w *WinEventLogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (w *WinEventLogSource) Dump() interface{} {
	return w
}
