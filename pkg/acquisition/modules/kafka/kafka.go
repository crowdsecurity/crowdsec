package kafkaacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/segmentio/kafka-go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var (
	dataSourceName = "kafka"
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_kafkasource_hits_total",
		Help: "Total lines that were read from topic",
	},
	[]string{"topic"})

type KafkaConfiguration struct {
	Brokers                           []string   `yaml:"brokers"`
	Topic                             string     `yaml:"topic"`
	GroupID                           string     `yaml:"group_id"`
	Timeout                           string     `yaml:"timeout"`
	TLS                               *TLSConfig `yaml:"tls"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ClientCert         string `yaml:"client_cert"`
	ClientKey          string `yaml:"client_key"`
	CaCert             string `yaml:"ca_cert"`
}

type KafkaSource struct {
	Config KafkaConfiguration
	logger *log.Entry
	Reader *kafka.Reader
}

func (k *KafkaSource) GetUuid() string {
	return k.Config.UniqueId
}

func (k *KafkaSource) UnmarshalConfig(yamlConfig []byte) error {
	k.Config = KafkaConfiguration{}

	err := yaml.UnmarshalStrict(yamlConfig, &k.Config)
	if err != nil {
		return fmt.Errorf("cannot parse %s datasource configuration: %w", dataSourceName, err)
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

	return err
}

func (k *KafkaSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	k.logger = logger

	err := k.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	dialer, err := k.Config.NewDialer()
	if err != nil {
		return errors.Wrapf(err, "cannot create %s dialer", dataSourceName)
	}

	k.Reader, err = k.Config.NewReader(dialer)
	if err != nil {
		return errors.Wrapf(err, "cannote create %s reader", dataSourceName)
	}

	if k.Reader == nil {
		return fmt.Errorf("cannot create %s reader", dataSourceName)
	}

	return nil
}

func (k *KafkaSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("%s datasource does not support command-line acquisition", dataSourceName)
}

func (k *KafkaSource) GetMode() string {
	return k.Config.Mode
}

func (k *KafkaSource) GetName() string {
	return dataSourceName
}

func (k *KafkaSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("%s datasource does not support one-shot acquisition", dataSourceName)
}

func (k *KafkaSource) CanRun() error {
	return nil
}

func (k *KafkaSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (k *KafkaSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (k *KafkaSource) Dump() interface{} {
	return k
}

func (k *KafkaSource) ReadMessage(out chan types.Event) error {
	// Start processing from latest Offset
	k.Reader.SetOffsetAt(context.Background(), time.Now())
	for {
		m, err := k.Reader.ReadMessage(context.Background())
		if err != nil {
			if err == io.EOF {
				return nil
			}
			k.logger.Errorln(errors.Wrapf(err, "while reading %s message", dataSourceName))
		}
		l := types.Line{
			Raw:     string(m.Value),
			Labels:  k.Config.Labels,
			Time:    m.Time.UTC(),
			Src:     k.Config.Topic,
			Process: true,
			Module:  k.GetName(),
		}
		linesRead.With(prometheus.Labels{"topic": k.Config.Topic}).Inc()
		var evt types.Event

		if !k.Config.UseTimeMachine {
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
		} else {
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
		}
		out <- evt
	}
}

func (k *KafkaSource) RunReader(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		return k.ReadMessage(out)
	})
	//nolint //fp
	for {
		select {
		case <-t.Dying():
			k.logger.Infof("%s datasource topic %s stopping", dataSourceName, k.Config.Topic)
			if err := k.Reader.Close(); err != nil {
				return errors.Wrapf(err, "while closing  %s reader on topic '%s'", dataSourceName, k.Config.Topic)
			}
			return nil
		}
	}
}

func (k *KafkaSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	k.logger.Infof("start reader on topic '%s'", k.Config.Topic)

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/kafka/live")
		return k.RunReader(out, t)
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

	tlsConfig.BuildNameToCertificate()
	return &tlsConfig, err
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
	return dialer, nil
}

func (kc *KafkaConfiguration) NewReader(dialer *kafka.Dialer) (*kafka.Reader, error) {
	rConf := kafka.ReaderConfig{
		Brokers: kc.Brokers,
		Topic:   kc.Topic,
		Dialer:  dialer,
	}
	if kc.GroupID != "" {
		rConf.GroupID = kc.GroupID
	}
	if err := rConf.Validate(); err != nil {
		return &kafka.Reader{}, errors.Wrapf(err, "while validating reader configuration")
	}
	return kafka.NewReader(rConf), nil
}
