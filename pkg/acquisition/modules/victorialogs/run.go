package victorialogs

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs/internal/vlclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// OneShotAcquisition reads a set of file and returns when done
func (s *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.logger.Debug("VictoriaLogs one shot acquisition")
	s.Client.SetTomb(t)

	readyCtx, cancel := context.WithTimeout(ctx, s.Config.WaitForReady)
	defer cancel()

	err := s.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("VictoriaLogs is not ready: %w", err)
	}

	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	respChan := s.Client.QueryRange(ctx, false)

	for {
		select {
		case <-t.Dying():
			s.logger.Debug("VictoriaLogs one shot acquisition stopped")
			return nil
		case resp, ok := <-respChan:
			if !ok {
				s.logger.Info("VictoriaLogs acquisition completed")
				return nil
			}

			s.readOneEntry(ctx, resp, s.Config.Labels, out)
		}
	}
}

func (s *Source) readOneEntry(ctx context.Context, entry *vlclient.Log, labels map[string]string, out chan pipeline.Event) {
	ll := pipeline.Line{}
	ll.Raw = entry.Message
	ll.Time = entry.Time
	ll.Src = s.Config.URL
	ll.Labels = labels
	ll.Process = true
	ll.Module = s.GetName()

	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.VictorialogsDataSourceLinesRead.With(prometheus.Labels{"source": s.Config.URL, "datasource_type": ModuleName, "acquis_type": s.Config.Labels["type"]}).Inc()
	}

	expectMode := pipeline.LIVE
	if s.Config.UseTimeMachine {
		expectMode = pipeline.TIMEMACHINE
	}

	evt := pipeline.Event{
		Line:       ll,
		Process:    true,
		Type:       pipeline.LOG,
		ExpectMode: expectMode,
	}

	select {
	case out <- evt:
	case <-ctx.Done():
	}
}

// Stream tails VictoriaLogs until the server closes the stream.
func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logs := make(chan *vlclient.Log)
	errChan := make(chan error, 1)

	go func() {
		errChan <- s.Client.Tail(ctx, logs)
		close(logs)
	}()

	for entry := range logs {
		s.readOneEntry(ctx, entry, s.Config.Labels, out)
	}

	return <-errChan
}
