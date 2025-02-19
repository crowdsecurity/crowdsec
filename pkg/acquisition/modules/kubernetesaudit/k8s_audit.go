package kubernetesauditacquisition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
	"k8s.io/apiserver/pkg/apis/audit"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type KubernetesAuditConfiguration struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	WebhookPath                       string `yaml:"webhook_path"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type KubernetesAuditSource struct {
	metricsLevel int
	config       KubernetesAuditConfiguration
	logger       *log.Entry
	mux          *http.ServeMux
	server       *http.Server
	outChan      chan types.Event
	addr         string
}

var eventCount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_k8sauditsource_hits_total",
		Help: "Total number of events received by k8s-audit source",
	},
	[]string{"source"})

var requestCount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_k8sauditsource_requests_total",
		Help: "Total number of requests received",
	},
	[]string{"source"})

func (ka *KubernetesAuditSource) GetUuid() string {
	return ka.config.UniqueId
}

func (ka *KubernetesAuditSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{eventCount, requestCount}
}

func (ka *KubernetesAuditSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{eventCount, requestCount}
}

func (ka *KubernetesAuditSource) UnmarshalConfig(yamlConfig []byte) error {
	k8sConfig := KubernetesAuditConfiguration{}

	err := yaml.UnmarshalStrict(yamlConfig, &k8sConfig)
	if err != nil {
		return fmt.Errorf("cannot parse k8s-audit configuration: %w", err)
	}

	ka.config = k8sConfig

	if ka.config.ListenAddr == "" {
		return errors.New("listen_addr cannot be empty")
	}

	if ka.config.ListenPort == 0 {
		return errors.New("listen_port cannot be empty")
	}

	if ka.config.WebhookPath == "" {
		return errors.New("webhook_path cannot be empty")
	}

	if ka.config.WebhookPath[0] != '/' {
		ka.config.WebhookPath = "/" + ka.config.WebhookPath
	}

	if ka.config.Mode == "" {
		ka.config.Mode = configuration.TAIL_MODE
	}

	return nil
}

func (ka *KubernetesAuditSource) Configure(config []byte, logger *log.Entry, metricsLevel int) error {
	ka.logger = logger
	ka.metricsLevel = metricsLevel

	err := ka.UnmarshalConfig(config)
	if err != nil {
		return err
	}

	ka.logger.Tracef("K8SAudit configuration: %+v", ka.config)

	ka.addr = fmt.Sprintf("%s:%d", ka.config.ListenAddr, ka.config.ListenPort)

	ka.mux = http.NewServeMux()

	ka.server = &http.Server{
		Addr:      ka.addr,
		Handler:   ka.mux,
		Protocols: &http.Protocols{},
	}

	ka.server.Protocols.SetHTTP1(true)
	ka.server.Protocols.SetUnencryptedHTTP2(true)
	ka.server.Protocols.SetHTTP2(true)

	ka.mux.HandleFunc(ka.config.WebhookPath, ka.webhookHandler)

	return nil
}

func (ka *KubernetesAuditSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return errors.New("k8s-audit datasource does not support command-line acquisition")
}

func (ka *KubernetesAuditSource) GetMode() string {
	return ka.config.Mode
}

func (ka *KubernetesAuditSource) GetName() string {
	return "k8s-audit"
}

func (ka *KubernetesAuditSource) OneShotAcquisition(_ context.Context, _ chan types.Event, _ *tomb.Tomb) error {
	return errors.New("k8s-audit datasource does not support one-shot acquisition")
}

func (ka *KubernetesAuditSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	ka.outChan = out

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/k8s-audit/live")
		ka.logger.Infof("Starting k8s-audit server on %s:%d%s", ka.config.ListenAddr, ka.config.ListenPort, ka.config.WebhookPath)
		t.Go(func() error {
			err := ka.server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("k8s-audit server failed: %w", err)
			}

			return nil
		})
		<-t.Dying()
		ka.logger.Infof("Stopping k8s-audit server on %s:%d%s", ka.config.ListenAddr, ka.config.ListenPort, ka.config.WebhookPath)

		if err := ka.server.Shutdown(ctx); err != nil {
			ka.logger.Errorf("Error shutting down k8s-audit server: %s", err.Error())
		}

		return nil
	})

	return nil
}

func (ka *KubernetesAuditSource) CanRun() error {
	return nil
}

func (ka *KubernetesAuditSource) Dump() interface{} {
	return ka
}

func (ka *KubernetesAuditSource) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if ka.metricsLevel != configuration.METRICS_NONE {
		requestCount.WithLabelValues(ka.addr).Inc()
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ka.logger.Tracef("webhookHandler called")

	var auditEvents audit.EventList

	jsonBody, err := io.ReadAll(r.Body)
	if err != nil {
		ka.logger.Errorf("Error reading request body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	ka.logger.Tracef("webhookHandler receveid: %s", string(jsonBody))

	err = json.Unmarshal(jsonBody, &auditEvents)
	if err != nil {
		ka.logger.Errorf("Error decoding audit events: %s", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	remoteIP := strings.Split(r.RemoteAddr, ":")[0]

	for idx := range auditEvents.Items {
		if ka.metricsLevel != configuration.METRICS_NONE {
			eventCount.WithLabelValues(ka.addr).Inc()
		}

		bytesEvent, err := json.Marshal(auditEvents.Items[idx])
		if err != nil {
			ka.logger.Errorf("Error serializing audit event: %s", err)
			continue
		}

		ka.logger.Tracef("Got audit event: %s", string(bytesEvent))
		l := types.Line{
			Raw:     string(bytesEvent),
			Labels:  ka.config.Labels,
			Time:    auditEvents.Items[idx].StageTimestamp.Time,
			Src:     remoteIP,
			Process: true,
			Module:  ka.GetName(),
		}
		evt := types.MakeEvent(ka.config.UseTimeMachine, types.LOG, true)
		evt.Line = l
		ka.outChan <- evt
	}
}
