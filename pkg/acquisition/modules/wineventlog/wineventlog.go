//go:build !windows

package wineventlogacquisition

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type WinEventLogSource struct{}

func (*WinEventLogSource) GetUuid() string {
	return ""
}

func (*WinEventLogSource) UnmarshalConfig(_ []byte) error {
	return nil
}

func (*WinEventLogSource) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	return nil
}

func (*WinEventLogSource) ConfigureByDSN(_ context.Context, _ string, _ map[string]string, _ *log.Entry, _ string) error {
	return nil
}

func (*WinEventLogSource) GetMode() string {
	return ""
}

func (*WinEventLogSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (*WinEventLogSource) OneShotAcquisition(_ context.Context, _ chan types.Event, _ *tomb.Tomb) error {
	return nil
}

func (*WinEventLogSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (*WinEventLogSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (*WinEventLogSource) GetName() string {
	return "wineventlog"
}

func (*WinEventLogSource) CanRun() error {
	return errors.New("windows event log acquisition is only supported on Windows")
}

func (*WinEventLogSource) StreamingAcquisition(_ context.Context, _ chan types.Event, _ *tomb.Tomb) error {
	return nil
}

func (w *WinEventLogSource) Dump() any {
	return w
}
