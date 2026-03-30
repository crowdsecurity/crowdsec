package kafkaacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/segmentio/kafka-go"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	Brokers                           []string                `yaml:"brokers"`
	Topic                             string                  `yaml:"topic"`
	GroupID                           string                  `yaml:"group_id"`
	Partition                         int                     `yaml:"partition"`
	Timeout                           string                  `yaml:"timeout"`
	TLS                               *TLSConfig              `yaml:"tls"`
	BatchConfiguration                KafkaBatchConfiguration `yaml:"batch"`
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

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse: %s", yaml.FormatError(err, false, false))
	}

	if len(s.Config.Brokers) == 0 {
		return fmt.Errorf("cannot create a %s reader with an empty list of broker addresses", s.GetName())
	}

	if s.Config.Topic == "" {
		return fmt.Errorf("cannot create a %s reader with an empty topic", s.GetName())
	}

	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}

	s.logger.Debugf("successfully parsed kafka configuration : %+v", s.Config)

	return err
}

func (s *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	s.logger.Debugf("start configuring %s source", s.GetName())

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	dialer, err := s.Config.NewDialer()
	if err != nil {
		return fmt.Errorf("cannot create %s dialer: %w", s.GetName(), err)
	}

	s.Reader, err = s.Config.NewReader(dialer, s.logger)
	if err != nil {
		return fmt.Errorf("cannote create %s reader: %w", s.GetName(), err)
	}

	if s.Reader == nil {
		return fmt.Errorf("cannot create %s reader", s.GetName())
	}

	s.logger.Debugf("successfully configured %s source", s.GetName())

	return nil
}

func (c *Configuration) NewTLSConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: c.TLS.InsecureSkipVerify,
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.ClientCert, c.TLS.ClientKey)
	if err != nil {
		return &tlsConfig, err
	}

	tlsConfig.Certificates = []tls.Certificate{cert}

	caCert, err := os.ReadFile(c.TLS.CaCert)
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

func (c *Configuration) NewDialer() (*kafka.Dialer, error) {
	dialer := &kafka.Dialer{}
	timeoutDuration := time.Duration(10) * time.Second

	if c.Timeout != "" {
		intTimeout, err := strconv.Atoi(c.Timeout)
		if err != nil {
			return dialer, err
		}

		timeoutDuration = time.Duration(intTimeout) * time.Second
	}

	dialer = &kafka.Dialer{
		Timeout:   timeoutDuration,
		DualStack: true,
	}

	if c.TLS != nil {
		tlsConfig, err := c.NewTLSConfig()
		if err != nil {
			return dialer, err
		}

		dialer.TLS = tlsConfig
	}

	return dialer, nil
}

func (c *Configuration) NewReader(dialer *kafka.Dialer, logger *log.Entry) (*kafka.Reader, error) {
	rConf := kafka.ReaderConfig{
		Brokers:     c.Brokers,
		Topic:       c.Topic,
		Dialer:      dialer,
		Logger:      kafka.LoggerFunc(logger.Debugf),
		ErrorLogger: kafka.LoggerFunc(logger.Errorf),
	}

	if c.GroupID != "" && c.Partition != 0 {
		return &kafka.Reader{}, errors.New("cannot specify both group_id and partition")
	}

	if c.GroupID != "" {
		rConf.GroupID = c.GroupID
		// kafka-go does not support calling SetOffset while using a consumer group
		rConf.StartOffset = kafka.LastOffset
	} else if c.Partition != 0 {
		rConf.Partition = c.Partition
	} else {
		logger.Warnf("no group_id specified, crowdsec will only read from the 1st partition of the topic")
	}

	if c.BatchConfiguration.BatchMinBytes != 0 {
		rConf.MinBytes = c.BatchConfiguration.BatchMinBytes
	}

	if c.BatchConfiguration.BatchMaxBytes != 0 {
		rConf.MaxBytes = c.BatchConfiguration.BatchMaxBytes
	}

	if c.BatchConfiguration.BatchMaxWait != 0 {
		rConf.MaxWait = c.BatchConfiguration.BatchMaxWait
	}

	if c.BatchConfiguration.BatchQueueSize != 0 {
		rConf.QueueCapacity = c.BatchConfiguration.BatchQueueSize
	}

	if c.BatchConfiguration.CommitInterval != 0 {
		rConf.CommitInterval = c.BatchConfiguration.CommitInterval
	}

	if err := rConf.Validate(); err != nil {
		return &kafka.Reader{}, fmt.Errorf("while validating reader configuration: %w", err)
	}

	return kafka.NewReader(rConf), nil
}
