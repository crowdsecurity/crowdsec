package kafkaacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const dataSourceName = "kafka"

type KafkaConfiguration struct {
	Brokers                           []string                `yaml:"brokers"`
	Topic                             string                  `yaml:"topic"`
	GroupID                           string                  `yaml:"group_id"`
	Partition                         int                     `yaml:"partition"`
	Timeout                           string                  `yaml:"timeout"`
	TLS                               *TLSConfig              `yaml:"tls"`
	BatchConfiguration                KafkaBatchConfiguration `yaml:"batch"`
	SASL                              *SASLConfig             `yaml:"sasl"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ClientCert         string `yaml:"client_cert"`
	ClientKey          string `yaml:"client_key"`
	CaCert             string `yaml:"ca_cert"`
}

type KafkaBatchConfiguration struct {
	BatchMinBytes  int           `yaml:"min_bytes"`
	BatchMaxBytes  int           `yaml:"max_bytes"`
	BatchMaxWait   time.Duration `yaml:"max_wait"`
	BatchQueueSize int           `yaml:"queue_size"`
	CommitInterval time.Duration `yaml:"commit_interval"`
}

type SASLConfig struct {
	Mechanism string `yaml:"mechanism"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	UseSSL    bool   `yaml:"use_ssl"`
}

type KafkaSource struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       KafkaConfiguration
	logger       *log.Entry
	Reader       *kafka.Reader
}

func (k *KafkaSource) GetUuid() string {
	return k.Config.UniqueId
}

func (k *KafkaSource) UnmarshalConfig(yamlConfig []byte) error {
	k.Config = KafkaConfiguration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &k.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse %s datasource configuration: %s", dataSourceName, yaml.FormatError(err, false, false))
	}

	if len(k.Config.Brokers) == 0 {
		return fmt.Errorf("cannot create a %s reader with an empty list of broker addresses", dataSourceName)
	}

	if k.Config.Topic == "" {
		return fmt.Errorf("cannot create a %s reader with am empty topic", dataSourceName)
	}

	if k.Config.Mode == "" {
		k.Config.Mode = configuration.TAIL_MODE
	}

	k.logger.Debugf("successfully parsed kafka configuration : %+v", k.Config)

	return err
}

func (k *KafkaSource) Configure(yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	k.logger = logger
	k.metricsLevel = metricsLevel

	k.logger.Debugf("start configuring %s source", dataSourceName)

	err := k.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	dialer, err := k.Config.NewDialer()
	if err != nil {
		return fmt.Errorf("cannot create %s dialer: %w", dataSourceName, err)
	}

	k.Reader, err = k.Config.NewReader(dialer, k.logger)
	if err != nil {
		return fmt.Errorf("cannote create %s reader: %w", dataSourceName, err)
	}

	if k.Reader == nil {
		return fmt.Errorf("cannot create %s reader", dataSourceName)
	}

	k.logger.Debugf("successfully configured %s source", dataSourceName)

	return nil
}

func (*KafkaSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("%s datasource does not support command-line acquisition", dataSourceName)
}

func (k *KafkaSource) GetMode() string {
	return k.Config.Mode
}

func (*KafkaSource) GetName() string {
	return dataSourceName
}

func (*KafkaSource) OneShotAcquisition(_ context.Context, _ chan types.Event, _ *tomb.Tomb) error {
	return fmt.Errorf("%s datasource does not support one-shot acquisition", dataSourceName)
}

func (*KafkaSource) CanRun() error {
	return nil
}

func (*KafkaSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.KafkaDataSourceLinesRead}
}

func (*KafkaSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.KafkaDataSourceLinesRead}
}

func (k *KafkaSource) Dump() any {
	return k
}

func (k *KafkaSource) ReadMessage(ctx context.Context, out chan types.Event) error {
	if k.Config.GroupID == "" {
		err := k.Reader.SetOffset(kafka.LastOffset)
		if err != nil {
			return fmt.Errorf("while setting offset for reader on topic '%s': %w", k.Config.Topic, err)
		}
	}

	for {
		k.logger.Tracef("reading message from topic '%s'", k.Config.Topic)

		m, err := k.Reader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			k.logger.Errorln(fmt.Errorf("while reading %s message: %w", dataSourceName, err))

			continue
		}

		k.logger.Tracef("got message: %s", string(m.Value))
		l := types.Line{
			Raw:     string(m.Value),
			Labels:  k.Config.Labels,
			Time:    m.Time.UTC(),
			Src:     k.Config.Topic,
			Process: true,
			Module:  k.GetName(),
		}
		k.logger.Tracef("line with message read from topic '%s': %+v", k.Config.Topic, l)

		if k.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.KafkaDataSourceLinesRead.With(prometheus.Labels{"topic": k.Config.Topic, "datasource_type": "kafka", "acquis_type": l.Labels["type"]}).Inc()
		}

		evt := types.MakeEvent(k.Config.UseTimeMachine, types.LOG, true)
		evt.Line = l
		out <- evt
	}
}

func (k *KafkaSource) RunReader(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	k.logger.Debugf("starting %s datasource reader goroutine with configuration %+v", dataSourceName, k.Config)
	t.Go(func() error {
		return k.ReadMessage(ctx, out)
	})
	//nolint //fp
	for {
		select {
		case <-t.Dying():
			k.logger.Infof("%s datasource topic %s stopping", dataSourceName, k.Config.Topic)
			if err := k.Reader.Close(); err != nil {
				return fmt.Errorf("while closing  %s reader on topic '%s': %w", dataSourceName, k.Config.Topic, err)
			}
			return nil
		}
	}
}

func (k *KafkaSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	k.logger.Infof("start reader on brokers '%+v' with topic '%s'", k.Config.Brokers, k.Config.Topic)

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/kafka/live")
		return k.RunReader(ctx, out, t)
	})

	return nil
}

func (kc *KafkaConfiguration) NewTLSConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: kc.TLS.InsecureSkipVerify,
	}

	cert, err := tls.LoadX509KeyPair(kc.TLS.ClientCert, kc.TLS.ClientKey)
	if err != nil {
		return &tlsConfig, err
	}

	tlsConfig.Certificates = []tls.Certificate{cert}

	caCert, err := os.ReadFile(kc.TLS.CaCert)
	if err != nil {
		return &tlsConfig, err
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return &tlsConfig, fmt.Errorf("unable to load system CA certificates: %w", err)
	}

	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}

	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig.RootCAs = caCertPool

	return &tlsConfig, err
}

func (kc *KafkaConfiguration) NewSASLConfig() (sasl.Mechanism, error) {
	if kc.SASL == nil {
		return nil, errors.New("SASL not configured")
	}
	if kc.SASL.Mechanism == "PLAIN" {
		mechanism := plain.Mechanism{
			Username: kc.SASL.Username,
			Password: kc.SASL.Password,
		}
		return mechanism, nil
	}
	return nil, fmt.Errorf("unsupported sasl mechanism: %s", kc.SASL.Mechanism)
}

func (kc *KafkaConfiguration) NewDialer() (*kafka.Dialer, error) {
	dialer := &kafka.Dialer{}
	var timeoutDuration time.Duration
	timeoutDuration = time.Duration(10) * time.Second
	if kc.Timeout != "" {
		intTimeout, err := strconv.Atoi(kc.Timeout)
		if err != nil {
			return dialer, err
		}
		timeoutDuration = time.Duration(intTimeout) * time.Second
	}
	dialer = &kafka.Dialer{
		Timeout:   timeoutDuration,
		DualStack: true,
	}

	if kc.TLS != nil {
		tlsConfig, err := kc.NewTLSConfig()
		if err != nil {
			return dialer, err
		}
		dialer.TLS = tlsConfig
	}

	if kc.SASL != nil {

		if kc.SASL.UseSSL && kc.TLS == nil {
			// If SASL requires SSL but no SSL config has been set up above,
			// we create a default one by passing an empty TLS Config to the dialer.
			tlsConfig := tls.Config{}
			dialer.TLS = &tlsConfig
		}

		saslMechanism, err := kc.NewSASLConfig()
		if err != nil {
			return dialer, err
		}
		dialer.SASLMechanism = saslMechanism
	}
	return dialer, nil
}

func (kc *KafkaConfiguration) NewReader(dialer *kafka.Dialer, logger *log.Entry) (*kafka.Reader, error) {
	rConf := kafka.ReaderConfig{
		Brokers:     kc.Brokers,
		Topic:       kc.Topic,
		Dialer:      dialer,
		Logger:      kafka.LoggerFunc(logger.Debugf),
		ErrorLogger: kafka.LoggerFunc(logger.Errorf),
	}

	if kc.GroupID != "" && kc.Partition != 0 {
		return &kafka.Reader{}, errors.New("cannot specify both group_id and partition")
	}

	if kc.GroupID != "" {
		rConf.GroupID = kc.GroupID
		// kafka-go does not support calling SetOffset while using a consumer group
		rConf.StartOffset = kafka.LastOffset
	} else if kc.Partition != 0 {
		rConf.Partition = kc.Partition
	} else {
		logger.Warnf("no group_id specified, crowdsec will only read from the 1st partition of the topic")
	}

	if kc.BatchConfiguration.BatchMinBytes != 0 {
		rConf.MinBytes = kc.BatchConfiguration.BatchMinBytes
	}
	if kc.BatchConfiguration.BatchMaxBytes != 0 {
		rConf.MaxBytes = kc.BatchConfiguration.BatchMaxBytes
	}
	if kc.BatchConfiguration.BatchMaxWait != 0 {
		rConf.MaxWait = kc.BatchConfiguration.BatchMaxWait
	}
	if kc.BatchConfiguration.BatchQueueSize != 0 {
		rConf.QueueCapacity = kc.BatchConfiguration.BatchQueueSize
	}
	if kc.BatchConfiguration.CommitInterval != 0 {
		rConf.CommitInterval = kc.BatchConfiguration.CommitInterval
	}

	if err := rConf.Validate(); err != nil {
		return &kafka.Reader{}, fmt.Errorf("while validating reader configuration: %w", err)
	}

	return kafka.NewReader(rConf), nil
}
