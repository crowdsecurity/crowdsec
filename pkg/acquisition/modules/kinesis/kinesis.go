package kinesisacquisition

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type KinesisConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	StreamName                        string  `yaml:"stream_name"`
	StreamARN                         string  `yaml:"stream_arn"`
	UseEnhancedFanOut                 bool    `yaml:"use_enhanced_fanout"` //Use RegisterStreamConsumer and SubscribeToShard instead of GetRecords
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         string  `yaml:"aws_region"`
	AwsEndpoint                       string  `yaml:"aws_endpoint"`
	ConsumerName                      string  `yaml:"consumer_name"`
	FromSubscription                  bool    `yaml:"from_subscription"`
	MaxRetries                        int     `yaml:"max_retries"`
}

type KinesisSource struct {
	Config          KinesisConfiguration
	logger          *log.Entry
	kClient         *kinesis.Kinesis
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

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_kinesis_stream_hits_total",
		Help: "Number of event read per stream.",
	},
	[]string{"stream"},
)

var linesReadShards = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_kinesis_shards_hits_total",
		Help: "Number of event read per shards.",
	},
	[]string{"stream", "shard"},
)

func (k *KinesisSource) GetUuid() string {
	return k.Config.UniqueId
}

func (k *KinesisSource) newClient() error {
	var sess *session.Session

	if k.Config.AwsProfile != nil {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Profile:           *k.Config.AwsProfile,
		}))
	} else {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
	}

	if sess == nil {
		return fmt.Errorf("failed to create aws session")
	}
	config := aws.NewConfig()
	if k.Config.AwsRegion != "" {
		config = config.WithRegion(k.Config.AwsRegion)
	}
	if k.Config.AwsEndpoint != "" {
		config = config.WithEndpoint(k.Config.AwsEndpoint)
	}
	k.kClient = kinesis.New(sess, config)
	if k.kClient == nil {
		return fmt.Errorf("failed to create kinesis client")
	}
	return nil
}

func (k *KinesisSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead, linesReadShards}

}
func (k *KinesisSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead, linesReadShards}
}

func (k *KinesisSource) UnmarshalConfig(yamlConfig []byte) error {
	k.Config = KinesisConfiguration{}

	err := yaml.UnmarshalStrict(yamlConfig, &k.Config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse kinesis datasource configuration")
	}

	if k.Config.Mode == "" {
		k.Config.Mode = configuration.TAIL_MODE
	}

	if k.Config.StreamName == "" && !k.Config.UseEnhancedFanOut {
		return fmt.Errorf("stream_name is mandatory when use_enhanced_fanout is false")
	}
	if k.Config.StreamARN == "" && k.Config.UseEnhancedFanOut {
		return fmt.Errorf("stream_arn is mandatory when use_enhanced_fanout is true")
	}
	if k.Config.ConsumerName == "" && k.Config.UseEnhancedFanOut {
		return fmt.Errorf("consumer_name is mandatory when use_enhanced_fanout is true")
	}
	if k.Config.StreamARN != "" && k.Config.StreamName != "" {
		return fmt.Errorf("stream_arn and stream_name are mutually exclusive")
	}
	if k.Config.MaxRetries <= 0 {
		k.Config.MaxRetries = 10
	}

	return nil
}

func (k *KinesisSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	k.logger = logger

	err := k.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	err = k.newClient()
	if err != nil {
		return fmt.Errorf("cannot create kinesis client: %w", err)
	}

	k.shardReaderTomb = &tomb.Tomb{}
	return nil
}

func (k *KinesisSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("kinesis datasource does not support command-line acquisition")
}

func (k *KinesisSource) GetMode() string {
	return k.Config.Mode
}

func (k *KinesisSource) GetName() string {
	return "kinesis"
}

func (k *KinesisSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("kinesis datasource does not support one-shot acquisition")
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

func (k *KinesisSource) WaitForConsumerDeregistration(consumerName string, streamARN string) error {
	maxTries := k.Config.MaxRetries
	for i := 0; i < maxTries; i++ {
		_, err := k.kClient.DescribeStreamConsumer(&kinesis.DescribeStreamConsumerInput{
			ConsumerName: aws.String(consumerName),
			StreamARN:    aws.String(streamARN),
		})
		if err != nil {
			switch err.(type) {
			case *kinesis.ResourceNotFoundException:
				return nil
			default:
				k.logger.Errorf("Error while waiting for consumer deregistration: %s", err)
				return errors.Wrap(err, "Cannot describe stream consumer")
			}
		}
		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
	}
	return fmt.Errorf("consumer %s is not deregistered after %d tries", consumerName, maxTries)
}

func (k *KinesisSource) DeregisterConsumer() error {
	k.logger.Debugf("Deregistering consumer %s if it exists", k.Config.ConsumerName)
	_, err := k.kClient.DeregisterStreamConsumer(&kinesis.DeregisterStreamConsumerInput{
		ConsumerName: aws.String(k.Config.ConsumerName),
		StreamARN:    aws.String(k.Config.StreamARN),
	})
	if err != nil {
		switch err.(type) {
		case *kinesis.ResourceNotFoundException:
		default:
			return errors.Wrap(err, "Cannot deregister stream consumer")
		}
	}
	err = k.WaitForConsumerDeregistration(k.Config.ConsumerName, k.Config.StreamARN)
	if err != nil {
		return errors.Wrap(err, "Cannot wait for consumer deregistration")
	}
	return nil
}

func (k *KinesisSource) WaitForConsumerRegistration(consumerARN string) error {
	maxTries := k.Config.MaxRetries
	for i := 0; i < maxTries; i++ {
		describeOutput, err := k.kClient.DescribeStreamConsumer(&kinesis.DescribeStreamConsumerInput{
			ConsumerARN: aws.String(consumerARN),
		})
		if err != nil {
			return errors.Wrap(err, "Cannot describe stream consumer")
		}
		if *describeOutput.ConsumerDescription.ConsumerStatus == "ACTIVE" {
			k.logger.Debugf("Consumer %s is active", consumerARN)
			return nil
		}
		time.Sleep(time.Millisecond * 200 * time.Duration(i+1))
		k.logger.Debugf("Waiting for consumer registration %d", i)
	}
	return fmt.Errorf("consumer %s is not active after %d tries", consumerARN, maxTries)
}

func (k *KinesisSource) RegisterConsumer() (*kinesis.RegisterStreamConsumerOutput, error) {
	k.logger.Debugf("Registering consumer %s", k.Config.ConsumerName)
	streamConsumer, err := k.kClient.RegisterStreamConsumer(&kinesis.RegisterStreamConsumerInput{
		ConsumerName: aws.String(k.Config.ConsumerName),
		StreamARN:    aws.String(k.Config.StreamARN),
	})
	if err != nil {
		return nil, errors.Wrap(err, "Cannot register stream consumer")
	}
	err = k.WaitForConsumerRegistration(*streamConsumer.Consumer.ConsumerARN)
	if err != nil {
		return nil, errors.Wrap(err, "Timeout while waiting for consumer to be active")
	}
	return streamConsumer, nil
}

func (k *KinesisSource) ParseAndPushRecords(records []*kinesis.Record, out chan types.Event, logger *log.Entry, shardId string) {
	for _, record := range records {
		if k.Config.StreamARN != "" {
			linesReadShards.With(prometheus.Labels{"stream": k.Config.StreamARN, "shard": shardId}).Inc()
			linesRead.With(prometheus.Labels{"stream": k.Config.StreamARN}).Inc()
		} else {
			linesReadShards.With(prometheus.Labels{"stream": k.Config.StreamName, "shard": shardId}).Inc()
			linesRead.With(prometheus.Labels{"stream": k.Config.StreamName}).Inc()
		}
		var data []CloudwatchSubscriptionLogEvent
		var err error
		if k.Config.FromSubscription {
			//The AWS docs says that the data is base64 encoded
			//but apparently GetRecords decodes it for us ?
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
			if k.Config.StreamARN != "" {
				l.Src = k.Config.StreamARN
			} else {
				l.Src = k.Config.StreamName
			}
			var evt types.Event
			if !k.Config.UseTimeMachine {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
			} else {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
			}
			out <- evt
		}
	}
}

func (k *KinesisSource) ReadFromSubscription(reader kinesis.SubscribeToShardEventStreamReader, out chan types.Event, shardId string, streamName string) error {
	logger := k.logger.WithFields(log.Fields{"shard_id": shardId})
	//ghetto sync, kinesis allows to subscribe to a closed shard, which will make the goroutine exit immediately
	//and we won't be able to start a new one if this is the first one started by the tomb
	//TODO: look into parent shards to see if a shard is closed before starting to read it ?
	time.Sleep(time.Second)
	for {
		select {
		case <-k.shardReaderTomb.Dying():
			logger.Infof("Subscribed shard reader is dying")
			err := reader.Close()
			if err != nil {
				return errors.Wrap(err, "Cannot close kinesis subscribed shard reader")
			}
			return nil
		case event, ok := <-reader.Events():
			if !ok {
				logger.Infof("Event chan has been closed")
				return nil
			}
			switch event := event.(type) {
			case *kinesis.SubscribeToShardEvent:
				k.ParseAndPushRecords(event.Records, out, logger, shardId)
			case *kinesis.SubscribeToShardEventStreamUnknownEvent:
				logger.Infof("got an unknown event, what to do ?")
			}
		}
	}
}

func (k *KinesisSource) SubscribeToShards(arn arn.ARN, streamConsumer *kinesis.RegisterStreamConsumerOutput, out chan types.Event) error {
	shards, err := k.kClient.ListShards(&kinesis.ListShardsInput{
		StreamName: aws.String(arn.Resource[7:]),
	})
	if err != nil {
		return errors.Wrap(err, "Cannot list shards for enhanced_read")
	}

	for _, shard := range shards.Shards {
		shardId := *shard.ShardId
		r, err := k.kClient.SubscribeToShard(&kinesis.SubscribeToShardInput{
			ShardId:          aws.String(shardId),
			StartingPosition: &kinesis.StartingPosition{Type: aws.String(kinesis.ShardIteratorTypeLatest)},
			ConsumerARN:      streamConsumer.Consumer.ConsumerARN,
		})
		if err != nil {
			return errors.Wrap(err, "Cannot subscribe to shard")
		}
		k.shardReaderTomb.Go(func() error {
			return k.ReadFromSubscription(r.GetEventStream().Reader, out, shardId, arn.Resource[7:])
		})
	}
	return nil
}

func (k *KinesisSource) EnhancedRead(out chan types.Event, t *tomb.Tomb) error {
	parsedARN, err := arn.Parse(k.Config.StreamARN)
	if err != nil {
		return errors.Wrap(err, "Cannot parse stream ARN")
	}
	if !strings.HasPrefix(parsedARN.Resource, "stream/") {
		return fmt.Errorf("resource part of stream ARN %s does not start with stream/", k.Config.StreamARN)
	}

	k.logger = k.logger.WithFields(log.Fields{"stream": parsedARN.Resource[7:]})
	k.logger.Info("starting kinesis acquisition with enhanced fan-out")
	err = k.DeregisterConsumer()
	if err != nil {
		return errors.Wrap(err, "Cannot deregister consumer")
	}

	streamConsumer, err := k.RegisterConsumer()
	if err != nil {
		return errors.Wrap(err, "Cannot register consumer")
	}

	for {
		k.shardReaderTomb = &tomb.Tomb{}

		err = k.SubscribeToShards(parsedARN, streamConsumer, out)
		if err != nil {
			return errors.Wrap(err, "Cannot subscribe to shards")
		}
		select {
		case <-t.Dying():
			k.logger.Infof("Kinesis source is dying")
			k.shardReaderTomb.Kill(nil)
			_ = k.shardReaderTomb.Wait() //we don't care about the error as we kill the tomb ourselves
			err = k.DeregisterConsumer()
			if err != nil {
				return errors.Wrap(err, "Cannot deregister consumer")
			}
			return nil
		case <-k.shardReaderTomb.Dying():
			k.logger.Debugf("Kinesis subscribed shard reader is dying")
			if k.shardReaderTomb.Err() != nil {
				return k.shardReaderTomb.Err()
			}
			//All goroutines have exited without error, so a resharding event, start again
			k.logger.Debugf("All reader goroutines have exited, resharding event or periodic resubscribe")
			continue
		}
	}
}

func (k *KinesisSource) ReadFromShard(out chan types.Event, shardId string) error {
	logger := k.logger.WithFields(log.Fields{"shard": shardId})
	logger.Debugf("Starting to read shard")
	sharIt, err := k.kClient.GetShardIterator(&kinesis.GetShardIteratorInput{ShardId: aws.String(shardId),
		StreamName:        &k.Config.StreamName,
		ShardIteratorType: aws.String(kinesis.ShardIteratorTypeLatest)})
	if err != nil {
		logger.Errorf("Cannot get shard iterator: %s", err)
		return errors.Wrap(err, "Cannot get shard iterator")
	}
	it := sharIt.ShardIterator
	//AWS recommends to wait for a second between calls to GetRecords for a given shard
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			records, err := k.kClient.GetRecords(&kinesis.GetRecordsInput{ShardIterator: it})
			it = records.NextShardIterator
			if err != nil {
				switch err.(type) {
				case *kinesis.ProvisionedThroughputExceededException:
					logger.Warn("Provisioned throughput exceeded")
					//TODO: implement exponential backoff
					continue
				case *kinesis.ExpiredIteratorException:
					logger.Warn("Expired iterator")
					continue
				default:
					logger.Error("Cannot get records")
					return errors.Wrap(err, "Cannot get records")
				}
			}
			k.ParseAndPushRecords(records.Records, out, logger, shardId)

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

func (k *KinesisSource) ReadFromStream(out chan types.Event, t *tomb.Tomb) error {
	k.logger = k.logger.WithFields(log.Fields{"stream": k.Config.StreamName})
	k.logger.Info("starting kinesis acquisition from shards")
	for {
		shards, err := k.kClient.ListShards(&kinesis.ListShardsInput{
			StreamName: aws.String(k.Config.StreamName),
		})
		if err != nil {
			return errors.Wrap(err, "Cannot list shards")
		}
		k.shardReaderTomb = &tomb.Tomb{}
		for _, shard := range shards.Shards {
			shardId := *shard.ShardId
			k.shardReaderTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/kinesis/streaming/shard")
				return k.ReadFromShard(out, shardId)
			})
		}
		select {
		case <-t.Dying():
			k.logger.Info("kinesis source is dying")
			k.shardReaderTomb.Kill(nil)
			_ = k.shardReaderTomb.Wait() //we don't care about the error as we kill the tomb ourselves
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

func (k *KinesisSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/kinesis/streaming")
		if k.Config.UseEnhancedFanOut {
			return k.EnhancedRead(out, t)
		} else {
			return k.ReadFromStream(out, t)
		}
	})
	return nil
}

func (k *KinesisSource) CanRun() error {
	return nil
}

func (k *KinesisSource) Dump() interface{} {
	return k
}
