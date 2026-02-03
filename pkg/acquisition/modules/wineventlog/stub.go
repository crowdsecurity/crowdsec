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
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Source struct{}

func (*Source) GetUuid() string {
	return ""
}

func (*Source) UnmarshalConfig(_ []byte) error {
	return nil
}

func (*Source) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	return nil
}

func (*Source) ConfigureByDSN(_ context.Context, _ string, _ map[string]string, _ *log.Entry, _ string) error {
	return nil
}

func (*Source) GetMode() string {
	return ""
}

func (*Source) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (*Source) OneShot(_ context.Context, _ chan pipeline.Event) error {
	return nil
}

func (*Source) GetMetrics() []prometheus.Collector {
	return nil
}

func (*Source) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (*Source) GetName() string {
	return ModuleName
}

func (*Source) CanRun() error {
	return errors.New("windows event log acquisition is only supported on Windows")
}

func (*Source) StreamingAcquisition(_ context.Context, _ chan pipeline.Event, _ *tomb.Tomb) error {
	return nil
}

func (w *Source) Dump() any {
	return w
}
