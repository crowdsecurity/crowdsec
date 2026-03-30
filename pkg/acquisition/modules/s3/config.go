package s3acquisition

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         string  `yaml:"aws_region"`
	AwsEndpoint                       string  `yaml:"aws_endpoint"`
	BucketName                        string  `yaml:"bucket_name"`
	Prefix                            string  `yaml:"prefix"`
	Key                               string  `yaml:"-"` // Only for DSN acquisition
	PollingMethod                     string  `yaml:"polling_method"`
	PollingInterval                   int     `yaml:"polling_interval"`
	SQSName                           string  `yaml:"sqs_name"`
	SQSFormat                         string  `yaml:"sqs_format"`
	MaxBufferSize                     int     `yaml:"max_buffer_size"`
}


const (
	PollMethodList          = "list"
	PollMethodSQS           = "sqs"
)

func (s *Source) newS3Client(ctx context.Context) (*s3.Client, error) {
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
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*s3.Options)
	if s.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(s.Config.AwsEndpoint)
		})
	}

	return s3.NewFromConfig(cfg, clientOpts...), nil
}

func (s *Source) newSQSClient(ctx context.Context) (*sqs.Client, error) {
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
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*sqs.Options)
	if s.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *sqs.Options) { o.BaseEndpoint = aws.String(s.Config.AwsEndpoint) })
	}

	return sqs.NewFromConfig(cfg, clientOpts...), nil
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse S3Acquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}

	if s.Config.PollingMethod == "" {
		s.Config.PollingMethod = PollMethodList
	}

	if s.Config.PollingInterval == 0 {
		s.Config.PollingInterval = 60
	}

	if s.Config.MaxBufferSize == 0 {
		s.Config.MaxBufferSize = bufio.MaxScanTokenSize
	}

	if s.Config.PollingMethod != PollMethodList && s.Config.PollingMethod != PollMethodSQS {
		return fmt.Errorf("invalid polling method %s", s.Config.PollingMethod)
	}

	if s.Config.BucketName != "" && s.Config.SQSName != "" {
		return errors.New("bucket_name and sqs_name are mutually exclusive")
	}

	if s.Config.PollingMethod == PollMethodSQS && s.Config.SQSName == "" {
		return errors.New("sqs_name is required when using sqs polling method")
	}

	if s.Config.BucketName == "" && s.Config.PollingMethod == PollMethodList {
		return errors.New("bucket_name is required")
	}

	if s.Config.SQSFormat != "" && s.Config.SQSFormat != SQSFormatEventBridge && s.Config.SQSFormat != SQSFormatS3Notification && s.Config.SQSFormat != SQSFormatSNS {
		return fmt.Errorf("invalid sqs_format %s, must be empty, %s, %s or %s", s.Config.SQSFormat, SQSFormatEventBridge, SQSFormatS3Notification, SQSFormatSNS)
	}

	return nil
}

func (s *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	if s.Config.SQSName != "" {
		s.logger = logger.WithFields(log.Fields{
			"queue": s.Config.SQSName,
		})
	} else {
		s.logger = logger.WithFields(log.Fields{
			"bucket": s.Config.BucketName,
			"prefix": s.Config.Prefix,
		})
	}

	if !s.Config.UseTimeMachine {
		s.logger.Warning("use_time_machine is not set to true in the datasource configuration. This will likely lead to false positives as S3 logs are not processed in real time.")
	}

	if s.Config.PollingMethod == PollMethodList {
		s.logger.Warning("Polling method is set to list. This is not recommended as it will not scale well. Consider using SQS instead.")
	}

	client, err := s.newS3Client(ctx)
	if err != nil {
		return err
	}

	s.s3Client = client

	if s.Config.PollingMethod == PollMethodSQS {
		sqsClient, err := s.newSQSClient(ctx)
		if err != nil {
			return err
		}

		s.sqsClient = sqsClient
	}

	return nil
}

func (s *Source) ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "s3://") {
		return fmt.Errorf("invalid DSN %s for S3 source, must start with s3://", dsn)
	}

	s.Config = Configuration{}
	s.logger = logger.WithFields(log.Fields{
		"bucket": s.Config.BucketName,
		"prefix": s.Config.Prefix,
	})

	dsn = strings.TrimPrefix(dsn, "s3://")
	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty s3:// DSN")
	}

	if len(args) == 2 && args[1] != "" {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse s3 args: %w", err)
		}

		for key, value := range params {
			switch key {
			case "log_level":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'log_level'")
				}

				lvl, err := log.ParseLevel(value[0])
				if err != nil {
					return fmt.Errorf("unknown level %s: %w", value[0], err)
				}

				s.logger.Logger.SetLevel(lvl)
			case "max_buffer_size":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'max_buffer_size'")
				}

				maxBufferSize, err := strconv.Atoi(value[0])
				if err != nil {
					return fmt.Errorf("invalid value for 'max_buffer_size': %w", err)
				}

				s.logger.Debugf("Setting max buffer size to %d", maxBufferSize)
				s.Config.MaxBufferSize = maxBufferSize
			default:
				return fmt.Errorf("unknown parameter %s", key)
			}
		}
	}

	s.Config.Labels = labels
	s.Config.Mode = configuration.CAT_MODE
	s.Config.UniqueId = uuid

	pathParts := strings.Split(args[0], "/")
	s.logger.Debugf("pathParts: %v", pathParts)

	// FIXME: handle s3://bucket/
	if len(pathParts) == 1 {
		s.Config.BucketName = pathParts[0]
		s.Config.Prefix = ""
	} else if len(pathParts) > 1 {
		s.Config.BucketName = pathParts[0]
		if args[0][len(args[0])-1] == '/' {
			s.Config.Prefix = strings.Join(pathParts[1:], "/")
		} else {
			s.Config.Key = strings.Join(pathParts[1:], "/")
		}
	} else {
		return fmt.Errorf("invalid DSN %s for S3 source", dsn)
	}

	client, err := s.newS3Client(ctx)
	if err != nil {
		return err
	}

	s.s3Client = client

	return nil
}
