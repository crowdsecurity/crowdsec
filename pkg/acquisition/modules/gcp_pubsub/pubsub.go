package gcppubsubacquisition

import (
	"cloud.google.com/go/pubsub"
	"context"
	"fmt"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type PubSubConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Subscription                      string `yaml:"subscription"`
	GcpRegion                         string `yaml:"gcp_region"`
	GcpProject                        string `yaml:"gcp_project"`
	MaxRetries                        int    `yaml:"max_retries"`
}

type PubSubSource struct {
	metricsLevel int
	Config       PubSubConfiguration
	logger       *log.Entry
	pClient      *pubsub.Client
	ctx          context.Context
}

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_pubsub_msg_hits_total",
		Help: "Number of messages read per subscription.",
	},
	[]string{"subscription"},
)

func (p *PubSubSource) GetUuid() string {
	return p.Config.UniqueId
}

func (p *PubSubSource) newClient() error {
	ctx := context.Background()
	credentials, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("could not find or generate default GCP credentials: %w", err)
	}
	client, err := pubsub.NewClient(ctx, p.Config.GcpProject, option.WithCredentials(credentials))
	if err != nil {
		return fmt.Errorf("cannot get pubsub client for project '%v' %w", p.Config.GcpProject, err)
	}
	p.pClient = client
	if p.pClient == nil {
		return fmt.Errorf("failed to create pubsub client")
	}
	return nil
}

func (p *PubSubSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}

}
func (p *PubSubSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (p *PubSubSource) UnmarshalConfig(yamlConfig []byte) error {
	p.Config = PubSubConfiguration{}

	err := yaml.UnmarshalStrict(yamlConfig, &p.Config)
	if err != nil {
		return fmt.Errorf("Cannot parse pubsub datasource configuration: %w", err)
	}

	if p.Config.Mode == "" {
		p.Config.Mode = configuration.TAIL_MODE
	}

	if p.Config.MaxRetries <= 0 {
		p.Config.MaxRetries = 10
	}

	return nil
}

func (p *PubSubSource) Configure(yamlConfig []byte, logger *log.Entry, MetricsLevel int) error {
	logger.Debugf("NON_ERROR start of pubsub configuration")

	p.logger = logger
	p.metricsLevel = MetricsLevel

	err := p.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}
	p.logger.Debugf("NON_ERROR pubsub configuration unmarshaled: %+v", p.Config)

	err = p.newClient()
	if err != nil {
		return fmt.Errorf("cannot create pubsub client: %w", err)
	}

	//p.logger.Debugf("NON_ERROR pubsub configuration: %+v", p.Config)
	return nil
}

func (p *PubSubSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("pubsub datasource does not support command-line acquisition")
}

func (p *PubSubSource) GetMode() string {
	return p.Config.Mode
}

func (p *PubSubSource) GetName() string {
	return "pubsub"
}

func (p *PubSubSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("pubsub datasource does not support one-shot acquisition")
}

func (p *PubSubSource) ParseAndPushRecords(msg *pubsub.Message, out chan types.Event, logger *log.Entry) {
	if p.metricsLevel != configuration.METRICS_NONE {
		linesRead.With(prometheus.Labels{"subscription": p.Config.Subscription}).Inc()
	}
	var data = string(msg.Data[:])
	logger.Tracef("got message %v", data)
	l := types.Line{}
	l.Raw = data
	l.Labels = p.Config.Labels
	l.Time = time.Now().UTC()
	l.Process = true
	l.Module = p.GetName()
	l.Src = p.Config.Subscription

	var evt types.Event
	if !p.Config.UseTimeMachine {
		evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
	} else {
		evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
	}
	out <- evt
	msg.Ack()

}

func (p *PubSubSource) StreamFromPubsub(out chan types.Event, t *tomb.Tomb) error {
	sub := p.pClient.Subscription(p.Config.Subscription)
	ctx := context.Background()
	err := sub.Receive(ctx, func(_ context.Context, m *pubsub.Message) {
		p.ParseAndPushRecords(m, out, p.logger)
	})
	if err != nil {
		p.logger.Errorf("Could not setup to receive from pubsub subscription '%v' due to %w", p.Config.Subscription, err.Error())
		return err
	}
	return nil
}

func (p *PubSubSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/pubsub/streaming")
		return p.StreamFromPubsub(out, t)
	})
	return nil
}

func (p *PubSubSource) CanRun() error {
	return nil
}

func (p *PubSubSource) Dump() interface{} {
	return p
}
