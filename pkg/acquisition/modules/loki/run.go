package loki

/*
https://grafana.com/docs/loki/latest/api/#get-lokiapiv1tail
*/

import (
	"context"
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki/internal/lokiclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// OneShotAcquisition reads a set of file and returns when done
func (l *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	l.logger.Debug("Loki one shot acquisition")
	l.Client.SetTomb(t)

	if !l.Config.NoReadyCheck {
		readyCtx, readyCancel := context.WithTimeout(ctx, l.Config.WaitForReady)
		defer readyCancel()

		if err := l.Client.Ready(readyCtx); err != nil {
			return fmt.Errorf("loki is not ready: %w", err)
		}
	}

	lokiCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := l.Client.QueryRange(lokiCtx, false)

	for {
		select {
		case <-t.Dying():
			l.logger.Debug("Loki one shot acquisition stopped")
			return nil
		case resp, ok := <-c:
			if !ok {
				l.logger.Info("Loki acquisition done, chan closed")
				return nil
			}

			for _, stream := range resp.Data.Result {
				for _, entry := range stream.Entries {
					l.readOneEntry(entry, l.Config.Labels, out)
				}
			}
		}
	}
}

func (l *Source) readOneEntry(entry lokiclient.Entry, labels map[string]string, out chan pipeline.Event) {
	ll := pipeline.Line{}
	ll.Raw = entry.Line
	ll.Time = entry.Timestamp
	ll.Src = l.Config.URL
	ll.Labels = labels
	ll.Process = true
	ll.Module = l.GetName()

	if l.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.LokiDataSourceLinesRead.With(prometheus.Labels{"source": l.Config.URL, "datasource_type": "loki", "acquis_type": ll.Labels["type"]}).Inc()
	}

	evt := pipeline.MakeEvent(l.Config.UseTimeMachine, pipeline.LOG, true)
	evt.Line = ll

	out <- evt
}

func (l *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	l.Client.SetTomb(t)

	if !l.Config.NoReadyCheck {
		readyCtx, readyCancel := context.WithTimeout(ctx, l.Config.WaitForReady)
		defer readyCancel()

		if err := l.Client.Ready(readyCtx); err != nil {
			return fmt.Errorf("loki is not ready: %w", err)
		}
	}

	ll := l.logger.WithField("websocket_url", l.lokiWebsocket)

	t.Go(func() error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		respChan := l.Client.QueryRange(ctx, true)

		for {
			select {
			case resp, ok := <-respChan:
				if !ok {
					ll.Warnf("loki channel closed")
					return errors.New("loki channel closed")
				}

				for _, stream := range resp.Data.Result {
					for _, entry := range stream.Entries {
						l.readOneEntry(entry, l.Config.Labels, out)
					}
				}
			case <-t.Dying():
				return nil
			}
		}
	})

	return nil
}
