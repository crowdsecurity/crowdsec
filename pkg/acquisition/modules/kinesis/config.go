package kinesisacquisition

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	StreamName        string  `yaml:"stream_name"`
	StreamARN         string  `yaml:"stream_arn"`
	UseEnhancedFanOut bool    `yaml:"use_enhanced_fanout"` // Use RegisterStreamConsumer and SubscribeToShard instead of GetRecords
	AwsProfile        *string `yaml:"aws_profile"`
	AwsRegion         string  `yaml:"aws_region"`
	AwsEndpoint       string  `yaml:"aws_endpoint"`
	ConsumerName      string  `yaml:"consumer_name"`
	FromSubscription  bool    `yaml:"from_subscription"`
	MaxRetries        int     `yaml:"max_retries"`
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse kinesis datasource configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}

	if s.Config.StreamName == "" && !s.Config.UseEnhancedFanOut {
		return errors.New("stream_name is mandatory when use_enhanced_fanout is false")
	}

	if s.Config.StreamARN == "" && s.Config.UseEnhancedFanOut {
		return errors.New("stream_arn is mandatory when use_enhanced_fanout is true")
	}

	if s.Config.ConsumerName == "" && s.Config.UseEnhancedFanOut {
		return errors.New("consumer_name is mandatory when use_enhanced_fanout is true")
	}

	if s.Config.StreamARN != "" && s.Config.StreamName != "" {
		return errors.New("stream_arn and stream_name are mutually exclusive")
	}

	if s.Config.MaxRetries <= 0 {
		s.Config.MaxRetries = 10
	}

	return nil
}

func (s *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	err = s.newClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create kinesis client: %w", err)
	}

	s.shardReaderTomb = &tomb.Tomb{}

	return nil
}

func (s *Source) newClient(ctx context.Context) error {
	var loadOpts []func(*config.LoadOptions) error
	if s.Config.AwsProfile != nil && *s.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*s.Config.AwsProfile))
	}

	region := s.Config.AwsRegion
	if region == "" {
		region = "us-east-1"
	}

	loadOpts = append(loadOpts, config.WithRegion(region))

	if c := defaultCreds(); c != nil {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(c))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*kinesis.Options)
	if s.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *kinesis.Options) {
			o.BaseEndpoint = aws.String(s.Config.AwsEndpoint)
		})
	}

	s.kClient = kinesis.NewFromConfig(cfg, clientOpts...)

	return nil
}
