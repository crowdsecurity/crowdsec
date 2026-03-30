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
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinTypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

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

func (s *Source) decodeFromSubscription(record []byte) ([]CloudwatchSubscriptionLogEvent, error) {
	b := bytes.NewBuffer(record)

	r, err := gzip.NewReader(b)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	decompressed, err := io.ReadAll(r)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	var subscriptionRecord CloudWatchSubscriptionRecord

	err = json.Unmarshal(decompressed, &subscriptionRecord)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return subscriptionRecord.LogEvents, nil
}

func (s *Source) WaitForConsumerDeregistration(ctx context.Context, consumerName string, streamARN string) error {
	maxTries := s.Config.MaxRetries
	for i := range maxTries {
		_, err := s.kClient.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{
				ConsumerName: aws.String(consumerName),
				StreamARN:    aws.String(streamARN),
			})

		var resourceNotFoundErr *kinTypes.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			return nil
		}

		if err != nil {
			s.logger.Errorf("Error while waiting for consumer deregistration: %s", err)
			return fmt.Errorf("cannot describe stream consumer: %w", err)
		}

		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
	}

	return fmt.Errorf("consumer %s is not deregistered after %d tries", consumerName, maxTries)
}

func (s *Source) DeregisterConsumer(ctx context.Context) error {
	s.logger.Debugf("Deregistering consumer %s if it exists", s.Config.ConsumerName)
	_, err := s.kClient.DeregisterStreamConsumer(ctx, &kinesis.DeregisterStreamConsumerInput{
			ConsumerName: aws.String(s.Config.ConsumerName),
			StreamARN:    aws.String(s.Config.StreamARN),
		})

	var resourceNotFoundErr *kinTypes.ResourceNotFoundException
	if errors.As(err, &resourceNotFoundErr) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("cannot deregister stream consumer: %w", err)
	}

	err = s.WaitForConsumerDeregistration(ctx, s.Config.ConsumerName, s.Config.StreamARN)
	if err != nil {
		return fmt.Errorf("cannot wait for consumer deregistration: %w", err)
	}

	return nil
}

func (s *Source) WaitForConsumerRegistration(ctx context.Context, consumerARN string) error {
	maxTries := s.Config.MaxRetries
	for i := range maxTries {
		describeOutput, err := s.kClient.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{
				ConsumerARN: aws.String(consumerARN),
			})
		if err != nil {
			return fmt.Errorf("cannot describe stream consumer: %w", err)
		}

		if describeOutput.ConsumerDescription.ConsumerStatus == "ACTIVE" {
			s.logger.Debugf("Consumer %s is active", consumerARN)
			return nil
		}

		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
		s.logger.Debugf("Waiting for consumer registration %d", i)
	}

	return fmt.Errorf("consumer %s is not active after %d tries", consumerARN, maxTries)
}

func (s *Source) RegisterConsumer(ctx context.Context) (*kinesis.RegisterStreamConsumerOutput, error) {
	s.logger.Debugf("Registering consumer %s", s.Config.ConsumerName)

	streamConsumer, err := s.kClient.RegisterStreamConsumer(ctx, &kinesis.RegisterStreamConsumerInput{
			ConsumerName: aws.String(s.Config.ConsumerName),
			StreamARN:    aws.String(s.Config.StreamARN),
		})
	if err != nil {
		return nil, fmt.Errorf("cannot register stream consumer: %w", err)
	}

	err = s.WaitForConsumerRegistration(ctx, *streamConsumer.Consumer.ConsumerARN)
	if err != nil {
		return nil, fmt.Errorf("timeout while waiting for consumer to be active: %w", err)
	}

	return streamConsumer, nil
}

func (s *Source) ParseAndPushRecords(records []kinTypes.Record, out chan pipeline.Event, logger *log.Entry, shardID string) {
	for _, record := range records {
		if s.Config.StreamARN != "" {
			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.KinesisDataSourceLinesReadShards.With(prometheus.Labels{"stream": s.Config.StreamARN, "shard": shardID}).Inc()
				metrics.KinesisDataSourceLinesRead.With(prometheus.Labels{"stream": s.Config.StreamARN, "datasource_type": ModuleName, "acquis_type": s.Config.Labels["type"]}).Inc()
			}
		} else {
			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.KinesisDataSourceLinesReadShards.With(prometheus.Labels{"stream": s.Config.StreamName, "shard": shardID}).Inc()
				metrics.KinesisDataSourceLinesRead.With(prometheus.Labels{"stream": s.Config.StreamName, "datasource_type": ModuleName, "acquis_type": s.Config.Labels["type"]}).Inc()
			}
		}

		var (
			data []CloudwatchSubscriptionLogEvent
			err  error
		)

		if s.Config.FromSubscription {
			// The AWS docs says that the data is base64 encoded
			// but apparently GetRecords decodes it for us ?
			data, err = s.decodeFromSubscription(record.Data)
			if err != nil {
				logger.Errorf("Cannot decode data: %s", err)
				continue
			}
		} else {
			data = []CloudwatchSubscriptionLogEvent{{Message: string(record.Data)}}
		}

		for _, event := range data {
			logger.Tracef("got record %s", event.Message)

			l := pipeline.Line{}
			l.Raw = event.Message
			l.Labels = s.Config.Labels
			l.Time = time.Now().UTC()
			l.Process = true
			l.Module = s.GetName()

			l.Src = s.Config.StreamARN
			if l.Src == "" {
				l.Src = s.Config.StreamName
			}

			evt := pipeline.MakeEvent(s.Config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = l

			out <- evt
		}
	}
}

func (s *Source) ReadFromSubscription(reader kinesis.SubscribeToShardEventStreamReader, out chan pipeline.Event, shardID string, streamName string) error {
	logger := s.logger.WithField("shard_id", shardID)
	// ghetto sync, kinesis allows to subscribe to a closed shard, which will make the goroutine exit immediately
	// and we won't be able to start a new one if this is the first one started by the tomb
	// TODO: look into parent shards to see if a shard is closed before starting to read it ?
	time.Sleep(time.Second)

	for {
		select {
		case <-s.shardReaderTomb.Dying():
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
				s.ParseAndPushRecords(et.Value.Records, out, logger, shardID)
			default:
				logger.Infof("unhandled SubscribeToShard event: %T", et)
			}
		}
	}
}

func (s *Source) SubscribeToShards(ctx context.Context, arn arn.ARN, streamConsumer *kinesis.RegisterStreamConsumerOutput, out chan pipeline.Event) error {
	shards, err := s.kClient.ListShards(ctx, &kinesis.ListShardsInput{
			StreamName: aws.String(arn.Resource[7:]),
		})
	if err != nil {
		return fmt.Errorf("cannot list shards for enhanced_read: %w", err)
	}

	for _, shard := range shards.Shards {
		shardID := *shard.ShardId

		r, err := s.kClient.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{
				ShardId:          aws.String(shardID),
				StartingPosition: &kinTypes.StartingPosition{Type: kinTypes.ShardIteratorTypeLatest},
				ConsumerARN:      streamConsumer.Consumer.ConsumerARN,
			})
		if err != nil {
			return fmt.Errorf("cannot subscribe to shard: %w", err)
		}

		s.shardReaderTomb.Go(func() error {
			return s.ReadFromSubscription(r.GetStream().Reader, out, shardID, arn.Resource[7:])
		})
	}

	return nil
}

func (s *Source) EnhancedRead(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	parsedARN, err := arn.Parse(s.Config.StreamARN)
	if err != nil {
		return fmt.Errorf("cannot parse stream ARN: %w", err)
	}

	if !strings.HasPrefix(parsedARN.Resource, "stream/") {
		return fmt.Errorf("resource part of stream ARN %s does not start with stream/", s.Config.StreamARN)
	}

	s.logger = s.logger.WithField("stream", parsedARN.Resource[7:])
	s.logger.Info("starting kinesis acquisition with enhanced fan-out")

	err = s.DeregisterConsumer(ctx)
	if err != nil {
		return fmt.Errorf("cannot deregister consumer: %w", err)
	}

	streamConsumer, err := s.RegisterConsumer(ctx)
	if err != nil {
		return fmt.Errorf("cannot register consumer: %w", err)
	}

	for {
		s.shardReaderTomb = &tomb.Tomb{}

		err = s.SubscribeToShards(ctx, parsedARN, streamConsumer, out)
		if err != nil {
			return fmt.Errorf("cannot subscribe to shards: %w", err)
		}

		select {
		case <-t.Dying():
			s.logger.Infof("Kinesis source is dying")
			s.shardReaderTomb.Kill(nil)
			_ = s.shardReaderTomb.Wait() // we don't care about the error as we kill the tomb ourselves

			err = s.DeregisterConsumer(ctx)
			if err != nil {
				return fmt.Errorf("cannot deregister consumer: %w", err)
			}

			return nil
		case <-s.shardReaderTomb.Dying():
			s.logger.Debugf("Kinesis subscribed shard reader is dying")

			if s.shardReaderTomb.Err() != nil {
				return s.shardReaderTomb.Err()
			}
			// All goroutines have exited without error, so a resharding event, start again
			s.logger.Debugf("All reader goroutines have exited, resharding event or periodic resubscribe")

			continue
		}
	}
}

func (s *Source) ReadFromShard(ctx context.Context, out chan pipeline.Event, shardID string) error {
	logger := s.logger.WithField("shard", shardID)
	logger.Debugf("Starting to read shard")

	sharIt, err := s.kClient.GetShardIterator(ctx,
		&kinesis.GetShardIteratorInput{
			ShardId:           aws.String(shardID),
			StreamName:        &s.Config.StreamName,
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
			records, err := s.kClient.GetRecords(ctx, &kinesis.GetRecordsInput{ShardIterator: it})

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

			it = records.NextShardIterator

			s.ParseAndPushRecords(records.Records, out, logger, shardID)

			if it == nil {
				logger.Warnf("Shard has been closed")
				return nil
			}
		case <-s.shardReaderTomb.Dying():
			logger.Infof("shardReaderTomb is dying, exiting ReadFromShard")
			ticker.Stop()

			return nil
		}
	}
}

func (s *Source) ReadFromStream(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.logger = s.logger.WithField("stream", s.Config.StreamName)
	s.logger.Info("starting kinesis acquisition from shards")

	for {
		shards, err := s.kClient.ListShards(ctx, &kinesis.ListShardsInput{
				StreamName: aws.String(s.Config.StreamName),
			})
		if err != nil {
			return fmt.Errorf("cannot list shards: %w", err)
		}

		s.shardReaderTomb = &tomb.Tomb{}

		for _, shard := range shards.Shards {
			shardID := *shard.ShardId

			s.shardReaderTomb.Go(func() error {
				defer trace.ReportPanic()
				return s.ReadFromShard(ctx, out, shardID)
			})
		}

		select {
		case <-t.Dying():
			s.logger.Info("kinesis source is dying")
			s.shardReaderTomb.Kill(nil)
			_ = s.shardReaderTomb.Wait() // we don't care about the error as we kill the tomb ourselves

			return nil
		case <-s.shardReaderTomb.Dying():
			reason := s.shardReaderTomb.Err()
			if reason != nil {
				s.logger.Errorf("Unexpected error from shard reader : %s", reason)
				return reason
			}

			s.logger.Infof("All shards have been closed, probably a resharding event, restarting acquisition")

			continue
		}
	}
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.ReportPanic()

		if s.Config.UseEnhancedFanOut {
			return s.EnhancedRead(ctx, out, t)
		}

		return s.ReadFromStream(ctx, out, t)
	})

	return nil
}
