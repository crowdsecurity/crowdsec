package kubernetesauditacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/tomb.v2"
	"k8s.io/apiserver/pkg/apis/audit"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.outChan = out

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/k8s-audit/live")

		s.logger.Infof("Starting k8s-audit server on %s:%d%s", s.config.ListenAddr, s.config.ListenPort, s.config.WebhookPath)

		t.Go(func() error {
			err := s.server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("k8s-audit server failed: %w", err)
			}

			return nil
		})
		<-t.Dying()
		s.logger.Infof("Stopping k8s-audit server on %s:%d%s", s.config.ListenAddr, s.config.ListenPort, s.config.WebhookPath)

		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Errorf("Error shutting down k8s-audit server: %s", err.Error())
		}

		return nil
	})

	return nil
}

func (s *Source) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.K8SAuditDataSourceRequestCount.WithLabelValues(s.addr).Inc()
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.logger.Tracef("webhookHandler called")

	var auditEvents audit.EventList

	jsonBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Errorf("Error reading request body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	s.logger.Tracef("webhookHandler receveid: %s", string(jsonBody))

	err = json.Unmarshal(jsonBody, &auditEvents)
	if err != nil {
		s.logger.Errorf("Error decoding audit events: %s", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	remoteIP := strings.Split(r.RemoteAddr, ":")[0]

	for idx := range auditEvents.Items {
		if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.K8SAuditDataSourceEventCount.With(prometheus.Labels{"source": s.addr, "datasource_type": "k8s-audit", "acquis_type": s.config.Labels["type"]}).Inc()
		}

		bytesEvent, err := json.Marshal(auditEvents.Items[idx])
		if err != nil {
			s.logger.Errorf("Error serializing audit event: %s", err)
			continue
		}

		s.logger.Tracef("Got audit event: %s", string(bytesEvent))
		l := pipeline.Line{
			Raw:     string(bytesEvent),
			Labels:  s.config.Labels,
			Time:    auditEvents.Items[idx].StageTimestamp.Time,
			Src:     remoteIP,
			Process: true,
			Module:  s.GetName(),
		}

		evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
		evt.Line = l

		s.outChan <- evt
	}
}
