package kubernetesauditacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
	"k8s.io/apiserver/pkg/apis/audit"
)

type KubernetesAuditConfiguration struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	WebhookPath                       string `yaml:"webhook_path"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type KubernetesAuditSource struct {
	config  KubernetesAuditConfiguration
	logger  *log.Entry
	mux     *http.ServeMux
	server  *http.Server
	outChan chan types.Event
	addr    string
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
		return errors.Wrap(err, "Cannot parse k8s-audit configuration")
	}

	ka.config = k8sConfig

	if ka.config.ListenAddr == "" {
		return fmt.Errorf("listen_addr cannot be empty")
	}

	if ka.config.ListenPort == 0 {
		return fmt.Errorf("listen_port cannot be empty")
	}

	if ka.config.WebhookPath == "" {
		return fmt.Errorf("webhook_path cannot be empty")
	}

	if ka.config.WebhookPath[0] != '/' {
		ka.config.WebhookPath = "/" + ka.config.WebhookPath
	}

	if ka.config.Mode == "" {
		ka.config.Mode = configuration.TAIL_MODE
	}
	return nil
}

func (ka *KubernetesAuditSource) Configure(config []byte, logger *log.Entry) error {
	ka.logger = logger

	err := ka.UnmarshalConfig(config)
	if err != nil {
		return err
	}

	ka.logger.Tracef("K8SAudit configuration: %+v", ka.config)

	ka.addr = fmt.Sprintf("%s:%d", ka.config.ListenAddr, ka.config.ListenPort)

	ka.mux = http.NewServeMux()

	ka.server = &http.Server{
		Addr:    ka.addr,
		Handler: ka.mux,
	}

	ka.mux.HandleFunc(ka.config.WebhookPath, ka.webhookHandler)
	return nil
}

func (ka *KubernetesAuditSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("k8s-audit datasource does not support command-line acquisition")
}

func (ka *KubernetesAuditSource) GetMode() string {
	return ka.config.Mode
}

func (ka *KubernetesAuditSource) GetName() string {
	return "k8s-audit"
}

func (ka *KubernetesAuditSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("k8s-audit datasource does not support one-shot acquisition")
}

func (ka *KubernetesAuditSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	ka.outChan = out
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/k8s-audit/live")
		ka.logger.Infof("Starting k8s-audit server on %s:%d%s", ka.config.ListenAddr, ka.config.ListenPort, ka.config.WebhookPath)
		t.Go(func() error {
			err := ka.server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return errors.Wrap(err, "k8s-audit server failed")
			}
			return nil
		})
		<-t.Dying()
		ka.logger.Infof("Stopping k8s-audit server on %s:%d%s", ka.config.ListenAddr, ka.config.ListenPort, ka.config.WebhookPath)
		ka.server.Shutdown(context.TODO())
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
	requestCount.WithLabelValues(ka.addr).Inc()
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
	for _, auditEvent := range auditEvents.Items {
		eventCount.WithLabelValues(ka.addr).Inc()
		bytesEvent, err := json.Marshal(auditEvent)
		if err != nil {
			ka.logger.Errorf("Error marshaling audit event: %s", err)
			continue
		}
		ka.logger.Tracef("Got audit event: %s", string(bytesEvent))
		l := types.Line{
			Raw:     string(bytesEvent),
			Labels:  ka.config.Labels,
			Time:    auditEvent.StageTimestamp.Time,
			Src:     remoteIP,
			Process: true,
			Module:  ka.GetName(),
		}
		ka.outChan <- types.Event{
			Line:       l,
			Process:    true,
			Type:       types.LOG,
			ExpectMode: types.LIVE,
		}
	}
}
