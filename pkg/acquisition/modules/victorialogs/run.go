package victorialogs

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
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

	respChan, err := s.getResponseChan(ctx, false)
	if err != nil {
		return fmt.Errorf("error when starting acquisition: %w", err)
	}

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

			s.readOneEntry(resp, s.Config.Labels, out)
		}
	}
}

func (s *Source) readOneEntry(entry *vlclient.Log, labels map[string]string, out chan pipeline.Event) {
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

	out <- pipeline.Event{
		Line:       ll,
		Process:    true,
		Type:       pipeline.LOG,
		ExpectMode: expectMode,
	}
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.Client.SetTomb(t)

	readyCtx, cancel := context.WithTimeout(ctx, s.Config.WaitForReady)
	defer cancel()

	err := s.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("VictoriaLogs is not ready: %w", err)
	}

	lctx, clientCancel := context.WithCancel(ctx)
	// Don't defer clientCancel(), the client outlives this function call

	t.Go(func() error {
		<-t.Dying()
		clientCancel()

		return nil
	})

	t.Go(func() error {
		respChan, err := s.getResponseChan(lctx, true)
		if err != nil {
			clientCancel()
			s.logger.Errorf("could not start VictoriaLogs tail: %s", err)

			return fmt.Errorf("while starting VictoriaLogs tail: %w", err)
		}

		for {
			select {
			case resp, ok := <-respChan:
				if !ok {
					s.logger.Warnf("VictoriaLogs channel closed")
					clientCancel()

					return err
				}

				s.readOneEntry(resp, s.Config.Labels, out)
			case <-t.Dying():
				clientCancel()
				return nil
			}
		}
	})

	return nil
}

func (s *Source) getResponseChan(ctx context.Context, infinite bool) (chan *vlclient.Log, error) {
	var (
		respChan chan *vlclient.Log
		err      error
	)

	if s.Config.Mode == configuration.TAIL_MODE {
		respChan, err = s.Client.Tail(ctx)
		if err != nil {
			s.logger.Errorf("could not start VictoriaLogs tail: %s", err)
			return respChan, fmt.Errorf("while starting VictoriaLogs tail: %w", err)
		}
	} else {
		respChan = s.Client.QueryRange(ctx, infinite)
	}

	return respChan, err
}
