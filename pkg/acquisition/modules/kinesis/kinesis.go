package kinesisacquisition

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type KinesisConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	StreamName                        string  `yaml:"stream_name"`
	ShardCount                        int     `yaml:"shard_count"`
	UseEnhancedFanOut                 bool    `yaml:"use_enhanced_fanout"` //Use RegisterStreamConsumer and SubscribeToShard instead of GetRecords
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         *string `yaml:"aws_region"`
}

type KinesisSource struct {
	Config          KinesisConfiguration
	logger          *log.Entry
	kClient         *kinesis.Kinesis
	shardReaderTomb *tomb.Tomb
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
	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		k.logger.Debugf("[testing] overloading endpoint with %s", v)
		k.kClient = kinesis.New(sess, aws.NewConfig().WithEndpoint(v))
	} else {
		k.kClient = kinesis.New(sess)
	}
	if k.kClient == nil {
		return fmt.Errorf("failed to create kinesis client")
	}
	return nil
}

func (k *KinesisSource) GetMetrics() []prometheus.Collector {
	return nil
}
func (k *KinesisSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (k *KinesisSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	config := KinesisConfiguration{}
	k.logger = logger
	err := yaml.UnmarshalStrict(yamlConfig, &config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse kinesis datasource configuration")
	}
	if config.Mode == "" {
		config.Mode = configuration.TAIL_MODE
	}
	k.Config = config
	if k.Config.StreamName == "" {
		return fmt.Errorf("stream_name is mandatory")
	}
	err = k.newClient()
	if err != nil {
		return errors.Wrap(err, "Cannot create kinesis client")
	}
	k.shardReaderTomb = &tomb.Tomb{}
	return nil
}

func (k *KinesisSource) ConfigureByDSN(string, map[string]string, *log.Entry) error {
	return nil
}

func (k *KinesisSource) GetMode() string {
	return k.Config.Mode
}

func (k *KinesisSource) GetName() string {
	return "kinesis"
}

func (k *KinesisSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (k *KinesisSource) EnhancedRead(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (k *KinesisSource) ReadFromShard(out chan types.Event, shardId string) error {
	k.logger.Infof("Starting to read shard %s", shardId)
	sharIt, err := k.kClient.GetShardIterator(&kinesis.GetShardIteratorInput{ShardId: aws.String(shardId),
		StreamName:        &k.Config.StreamName,
		ShardIteratorType: aws.String(kinesis.ShardIteratorTypeLatest)})
	if err != nil {
		return errors.Wrap(err, "Cannot get shard iterator")
	}
	it := sharIt.ShardIterator
	for {
		records, err := k.kClient.GetRecords(&kinesis.GetRecordsInput{ShardIterator: it})
		if err != nil {
			return errors.Wrap(err, "Cannot get records")
		}
		it = records.NextShardIterator
		for _, record := range records.Records {
			l := types.Line{}
			l.Raw = string(record.Data)
			l.Labels = k.Config.Labels
			l.Time = time.Now()
			l.Process = true
			l.Module = k.GetName()
			//linesRead.With(prometheus.Labels{"source": j.src}).Inc()
			evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leakybucket.LIVE}
			out <- evt
			k.logger.Infof("got record %s", record.Data)
		}
		if it == nil {
			k.logger.Warnf("Shard in stream %s has been closed", k.Config.StreamName)
			return nil
		}
		//AWS recommends to wait for a second before calling GetRecords again
		time.Sleep(time.Second)
	}
	return nil
}

//TODO: Handle KMS
func (k *KinesisSource) ReadFromStream(out chan types.Event, t *tomb.Tomb) error {
	shards, err := k.kClient.ListShards(&kinesis.ListShardsInput{
		StreamName: aws.String(k.Config.StreamName),
	})
	if err != nil {
		return errors.Wrap(err, "Cannot list shards")
	}
	spew.Dump(shards)
	for _, shard := range shards.Shards {
		k.shardReaderTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis/kinesis/streaming/shard")
			return k.ReadFromShard(out, *shard.ShardId)
		})
	}
	for {
		select {
		case <-t.Dying():
			k.logger.Info("[kinesis] dying")
			return nil
		case <-k.shardReaderTomb.Dying():
			k.logger.Info("[kinesis] shard dying")
			return nil
		}
	}
}

func (k *KinesisSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	k.logger.Info("[kinesis] starting kinesis acquisition")
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/kinesis/streaming")
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
