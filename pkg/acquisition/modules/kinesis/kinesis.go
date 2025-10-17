package kinesisacquisition

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinTypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type KinesisConfiguration struct {
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

type KinesisSource struct {
	metricsLevel    metrics.AcquisitionMetricsLevel
	Config          KinesisConfiguration
	logger          *log.Entry
	kClient         *kinesis.Client
	shardReaderTomb *tomb.Tomb
}

type CloudWatchSubscriptionRecord struct {
	MessageType         string                           `json:"messageType"`
	Owner               string                           `json:"owner"`
	LogGroup            string                           `json:"logGroup"`
	LogStream           string                           `json:"logStream"`
	SubscriptionFilters []string                         `json:"subscriptionFilters"`
	LogEvents           []CloudwatchSubscriptionLogEvent `json:"logEvents"`
}

type CloudwatchSubscriptionLogEvent struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

func (k *KinesisSource) GetUuid() string {
	return k.Config.UniqueId
}

func (k *KinesisSource) newClient(ctx context.Context) error {
	var loadOpts []func(*config.LoadOptions) error
	if k.Config.AwsProfile != nil && *k.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*k.Config.AwsProfile))
	}

	region := k.Config.AwsRegion
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
	if k.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *kinesis.Options) {
			o.BaseEndpoint = aws.String(k.Config.AwsEndpoint)
		})
	}

	k.kClient = kinesis.NewFromConfig(cfg, clientOpts...)

	return nil
}

func (*KinesisSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.KinesisDataSourceLinesRead, metrics.KinesisDataSourceLinesReadShards}
}

func (*KinesisSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.KinesisDataSourceLinesRead, metrics.KinesisDataSourceLinesReadShards}
}

func (k *KinesisSource) UnmarshalConfig(yamlConfig []byte) error {
	k.Config = KinesisConfiguration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &k.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse kinesis datasource configuration: %s", yaml.FormatError(err, false, false))
	}

	if k.Config.Mode == "" {
		k.Config.Mode = configuration.TAIL_MODE
	}

	if k.Config.StreamName == "" && !k.Config.UseEnhancedFanOut {
		return errors.New("stream_name is mandatory when use_enhanced_fanout is false")
	}

	if k.Config.StreamARN == "" && k.Config.UseEnhancedFanOut {
		return errors.New("stream_arn is mandatory when use_enhanced_fanout is true")
	}

	if k.Config.ConsumerName == "" && k.Config.UseEnhancedFanOut {
		return errors.New("consumer_name is mandatory when use_enhanced_fanout is true")
	}

	if k.Config.StreamARN != "" && k.Config.StreamName != "" {
		return errors.New("stream_arn and stream_name are mutually exclusive")
	}

	if k.Config.MaxRetries <= 0 {
		k.Config.MaxRetries = 10
	}

	return nil
}

func (k *KinesisSource) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	k.logger = logger
	k.metricsLevel = metricsLevel

	err := k.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	err = k.newClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create kinesis client: %w", err)
	}

	k.shardReaderTomb = &tomb.Tomb{}

	return nil
}

func (k *KinesisSource) GetMode() string {
	return k.Config.Mode
}

func (*KinesisSource) GetName() string {
	return "kinesis"
}

func (k *KinesisSource) decodeFromSubscription(record []byte) ([]CloudwatchSubscriptionLogEvent, error) {
	b := bytes.NewBuffer(record)

	r, err := gzip.NewReader(b)
	if err != nil {
		k.logger.Error(err)
		return nil, err
	}

	decompressed, err := io.ReadAll(r)
	if err != nil {
		k.logger.Error(err)
		return nil, err
	}

	var subscriptionRecord CloudWatchSubscriptionRecord

	err = json.Unmarshal(decompressed, &subscriptionRecord)
	if err != nil {
		k.logger.Error(err)
		return nil, err
	}

	return subscriptionRecord.LogEvents, nil
}

func (k *KinesisSource) WaitForConsumerDeregistration(ctx context.Context, consumerName string, streamARN string) error {
	maxTries := k.Config.MaxRetries
	for i := range maxTries {
		_, err := k.kClient.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{
				ConsumerName: aws.String(consumerName),
				StreamARN:    aws.String(streamARN),
			})

		var resourceNotFoundErr *kinTypes.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			return nil
		}

		if err != nil {
			k.logger.Errorf("Error while waiting for consumer deregistration: %s", err)
			return fmt.Errorf("cannot describe stream consumer: %w", err)
		}

		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
	}

	return fmt.Errorf("consumer %s is not deregistered after %d tries", consumerName, maxTries)
}

func (k *KinesisSource) DeregisterConsumer(ctx context.Context) error {
	k.logger.Debugf("Deregistering consumer %s if it exists", k.Config.ConsumerName)
	_, err := k.kClient.DeregisterStreamConsumer(ctx, &kinesis.DeregisterStreamConsumerInput{
			ConsumerName: aws.String(k.Config.ConsumerName),
			StreamARN:    aws.String(k.Config.StreamARN),
		})

	var resourceNotFoundErr *kinTypes.ResourceNotFoundException
	if errors.As(err, &resourceNotFoundErr) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("cannot deregister stream consumer: %w", err)
	}

	err = k.WaitForConsumerDeregistration(ctx, k.Config.ConsumerName, k.Config.StreamARN)
	if err != nil {
		return fmt.Errorf("cannot wait for consumer deregistration: %w", err)
	}

	return nil
}

func (k *KinesisSource) WaitForConsumerRegistration(ctx context.Context, consumerARN string) error {
	maxTries := k.Config.MaxRetries
	for i := range maxTries {
		describeOutput, err := k.kClient.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{
				ConsumerARN: aws.String(consumerARN),
			})
		if err != nil {
			return fmt.Errorf("cannot describe stream consumer: %w", err)
		}

		if describeOutput.ConsumerDescription.ConsumerStatus == "ACTIVE" {
			k.logger.Debugf("Consumer %s is active", consumerARN)
			return nil
		}

		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
		k.logger.Debugf("Waiting for consumer registration %d", i)
	}

	return fmt.Errorf("consumer %s is not active after %d tries", consumerARN, maxTries)
}

func (k *KinesisSource) RegisterConsumer(ctx context.Context) (*kinesis.RegisterStreamConsumerOutput, error) {
	k.logger.Debugf("Registering consumer %s", k.Config.ConsumerName)

	streamConsumer, err := k.kClient.RegisterStreamConsumer(ctx, &kinesis.RegisterStreamConsumerInput{
			ConsumerName: aws.String(k.Config.ConsumerName),
			StreamARN:    aws.String(k.Config.StreamARN),
		})
	if err != nil {
		return nil, fmt.Errorf("cannot register stream consumer: %w", err)
	}

	err = k.WaitForConsumerRegistration(ctx, *streamConsumer.Consumer.ConsumerARN)
	if err != nil {
		return nil, fmt.Errorf("timeout while waiting for consumer to be active: %w", err)
	}

	return streamConsumer, nil
}

func (k *KinesisSource) ParseAndPushRecords(records []kinTypes.Record, out chan types.Event, logger *log.Entry, shardID string) {
	for _, record := range records {
		if k.Config.StreamARN != "" {
			if k.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.KinesisDataSourceLinesReadShards.With(prometheus.Labels{"stream": k.Config.StreamARN, "shard": shardID}).Inc()
				metrics.KinesisDataSourceLinesRead.With(prometheus.Labels{"stream": k.Config.StreamARN, "datasource_type": "kinesis", "acquis_type": k.Config.Labels["type"]}).Inc()
			}
		} else {
			if k.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.KinesisDataSourceLinesReadShards.With(prometheus.Labels{"stream": k.Config.StreamName, "shard": shardID}).Inc()
				metrics.KinesisDataSourceLinesRead.With(prometheus.Labels{"stream": k.Config.StreamName, "datasource_type": "kinesis", "acquis_type": k.Config.Labels["type"]}).Inc()
			}
		}

		var (
			data []CloudwatchSubscriptionLogEvent
			err  error
		)

		if k.Config.FromSubscription {
			// The AWS docs says that the data is base64 encoded
			// but apparently GetRecords decodes it for us ?
			data, err = k.decodeFromSubscription(record.Data)
			if err != nil {
				logger.Errorf("Cannot decode data: %s", err)
				continue
			}
		} else {
			data = []CloudwatchSubscriptionLogEvent{{Message: string(record.Data)}}
		}

		for _, event := range data {
			logger.Tracef("got record %s", event.Message)

			l := types.Line{}
			l.Raw = event.Message
			l.Labels = k.Config.Labels
			l.Time = time.Now().UTC()
			l.Process = true
			l.Module = k.GetName()

			l.Src = k.Config.StreamARN
			if l.Src == "" {
				l.Src = k.Config.StreamName
			}

			evt := types.MakeEvent(k.Config.UseTimeMachine, types.LOG, true)
			evt.Line = l

			out <- evt
		}
	}
}

func (k *KinesisSource) ReadFromSubscription(reader kinesis.SubscribeToShardEventStreamReader, out chan types.Event, shardID string, streamName string) error {
	logger := k.logger.WithField("shard_id", shardID)
	// ghetto sync, kinesis allows to subscribe to a closed shard, which will make the goroutine exit immediately
	// and we won't be able to start a new one if this is the first one started by the tomb
	// TODO: look into parent shards to see if a shard is closed before starting to read it ?
	time.Sleep(time.Second)

	for {
		select {
		case <-k.shardReaderTomb.Dying():
			logger.Infof("Subscribed shard reader is dying")

			if err := reader.Close(); err != nil {
				return fmt.Errorf("cannot close kinesis subscribed shard reader: %w", err)
			}

			return nil
		case event, ok := <-reader.Events():
			if !ok {
				logger.Infof("Event chan has been closed")
				return nil
			}

			switch et := event.(type) {
			case *kinTypes.SubscribeToShardEventStreamMemberSubscribeToShardEvent:
				k.ParseAndPushRecords(et.Value.Records, out, logger, shardID)
			default:
				logger.Infof("unhandled SubscribeToShard event: %T", et)
			}
		}
	}
}

func (k *KinesisSource) SubscribeToShards(ctx context.Context, arn arn.ARN, streamConsumer *kinesis.RegisterStreamConsumerOutput, out chan types.Event) error {
	shards, err := k.kClient.ListShards(ctx, &kinesis.ListShardsInput{
			StreamName: aws.String(arn.Resource[7:]),
		})
	if err != nil {
		return fmt.Errorf("cannot list shards for enhanced_read: %w", err)
	}

	for _, shard := range shards.Shards {
		shardID := *shard.ShardId

		r, err := k.kClient.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{
				ShardId:          aws.String(shardID),
				StartingPosition: &kinTypes.StartingPosition{Type: kinTypes.ShardIteratorTypeLatest},
				ConsumerARN:      streamConsumer.Consumer.ConsumerARN,
			})
		if err != nil {
			return fmt.Errorf("cannot subscribe to shard: %w", err)
		}

		k.shardReaderTomb.Go(func() error {
			return k.ReadFromSubscription(r.GetStream().Reader, out, shardID, arn.Resource[7:])
		})
	}

	return nil
}

func (k *KinesisSource) EnhancedRead(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	parsedARN, err := arn.Parse(k.Config.StreamARN)
	if err != nil {
		return fmt.Errorf("cannot parse stream ARN: %w", err)
	}

	if !strings.HasPrefix(parsedARN.Resource, "stream/") {
		return fmt.Errorf("resource part of stream ARN %s does not start with stream/", k.Config.StreamARN)
	}

	k.logger = k.logger.WithField("stream", parsedARN.Resource[7:])
	k.logger.Info("starting kinesis acquisition with enhanced fan-out")

	err = k.DeregisterConsumer(ctx)
	if err != nil {
		return fmt.Errorf("cannot deregister consumer: %w", err)
	}

	streamConsumer, err := k.RegisterConsumer(ctx)
	if err != nil {
		return fmt.Errorf("cannot register consumer: %w", err)
	}

	for {
		k.shardReaderTomb = &tomb.Tomb{}

		err = k.SubscribeToShards(ctx, parsedARN, streamConsumer, out)
		if err != nil {
			return fmt.Errorf("cannot subscribe to shards: %w", err)
		}

		select {
		case <-t.Dying():
			k.logger.Infof("Kinesis source is dying")
			k.shardReaderTomb.Kill(nil)
			_ = k.shardReaderTomb.Wait() // we don't care about the error as we kill the tomb ourselves

			err = k.DeregisterConsumer(ctx)
			if err != nil {
				return fmt.Errorf("cannot deregister consumer: %w", err)
			}

			return nil
		case <-k.shardReaderTomb.Dying():
			k.logger.Debugf("Kinesis subscribed shard reader is dying")

			if k.shardReaderTomb.Err() != nil {
				return k.shardReaderTomb.Err()
			}
			// All goroutines have exited without error, so a resharding event, start again
			k.logger.Debugf("All reader goroutines have exited, resharding event or periodic resubscribe")

			continue
		}
	}
}

func (k *KinesisSource) ReadFromShard(ctx context.Context, out chan types.Event, shardID string) error {
	logger := k.logger.WithField("shard", shardID)
	logger.Debugf("Starting to read shard")

	sharIt, err := k.kClient.GetShardIterator(ctx,
		&kinesis.GetShardIteratorInput{
			ShardId:           aws.String(shardID),
			StreamName:        &k.Config.StreamName,
			ShardIteratorType: kinTypes.ShardIteratorTypeLatest,
		})
	if err != nil {
		logger.Errorf("Cannot get shard iterator: %s", err)
		return fmt.Errorf("cannot get shard iterator: %w", err)
	}

	it := sharIt.ShardIterator
	// AWS recommends to wait for a second between calls to GetRecords for a given shard
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C:
			records, err := k.kClient.GetRecords(ctx, &kinesis.GetRecordsInput{ShardIterator: it})
			it = records.NextShardIterator

			var throughputErr *kinTypes.ProvisionedThroughputExceededException
			if errors.As(err, &throughputErr) {
				logger.Warn("Provisioned throughput exceeded")
				// TODO: implement exponential backoff
				continue
			}

			var expiredIteratorErr *kinTypes.ExpiredIteratorException
			if errors.As(err, &expiredIteratorErr) {
				logger.Warn("Expired iterator")
				continue
			}

			if err != nil {
				logger.Error("Cannot get records")
				return fmt.Errorf("cannot get records: %w", err)
			}

			k.ParseAndPushRecords(records.Records, out, logger, shardID)

			it = records.NextShardIterator
			if it == nil {
				logger.Warnf("Shard has been closed")
				return nil
			}
		case <-k.shardReaderTomb.Dying():
			logger.Infof("shardReaderTomb is dying, exiting ReadFromShard")
			ticker.Stop()

			return nil
		}
	}
}

func (k *KinesisSource) ReadFromStream(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	k.logger = k.logger.WithField("stream", k.Config.StreamName)
	k.logger.Info("starting kinesis acquisition from shards")

	for {
		shards, err := k.kClient.ListShards(ctx, &kinesis.ListShardsInput{
				StreamName: aws.String(k.Config.StreamName),
			})
		if err != nil {
			return fmt.Errorf("cannot list shards: %w", err)
		}

		k.shardReaderTomb = &tomb.Tomb{}

		for _, shard := range shards.Shards {
			shardID := *shard.ShardId

			k.shardReaderTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/kinesis/streaming/shard")
				return k.ReadFromShard(ctx, out, shardID)
			})
		}

		select {
		case <-t.Dying():
			k.logger.Info("kinesis source is dying")
			k.shardReaderTomb.Kill(nil)
			_ = k.shardReaderTomb.Wait() // we don't care about the error as we kill the tomb ourselves

			return nil
		case <-k.shardReaderTomb.Dying():
			reason := k.shardReaderTomb.Err()
			if reason != nil {
				k.logger.Errorf("Unexpected error from shard reader : %s", reason)
				return reason
			}

			k.logger.Infof("All shards have been closed, probably a resharding event, restarting acquisition")

			continue
		}
	}
}

func (k *KinesisSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/kinesis/streaming")

		if k.Config.UseEnhancedFanOut {
			return k.EnhancedRead(ctx, out, t)
		}

		return k.ReadFromStream(ctx, out, t)
	})

	return nil
}

func (*KinesisSource) CanRun() error {
	return nil
}

func (k *KinesisSource) Dump() any {
	return k
}
