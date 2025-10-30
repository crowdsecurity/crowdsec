package kinesisacquisition

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func GenSubObject(t *testing.T, i int) []byte {
	r := CloudWatchSubscriptionRecord{
		MessageType:         "subscription",
		Owner:               "test",
		LogGroup:            "test",
		LogStream:           "test",
		SubscriptionFilters: []string{"filter1"},
		LogEvents: []CloudwatchSubscriptionLogEvent{
			{
				ID:        "testid",
				Message:   strconv.Itoa(i),
				Timestamp: time.Now().UTC().Unix(),
			},
		},
	}
	body, err := json.Marshal(r)
	require.NoError(t, err)

	var b bytes.Buffer

	gz := gzip.NewWriter(&b)
	_, err = gz.Write(body)
	require.NoError(t, err)
	gz.Close()
	// AWS actually base64 encodes the data, but it looks like kinesis automatically decodes it at some point
	// localstack does not do it, so let's just write a raw gzipped stream
	return b.Bytes()
}

func WriteToStream(t *testing.T, endpoint string, streamName string, count int, shards int, sub bool) {
	ctx := t.Context()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"), config.WithCredentialsProvider(aws.AnonymousCredentials{}))
	require.NoError(t, err)

	kinesisClient := kinesis.NewFromConfig(cfg, func(o *kinesis.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	for i := range count {
		partition := "partition"
		if shards != 1 {
			partition = fmt.Sprintf("partition-%d", i%shards)
		}

		var data []byte

		if sub {
			data = GenSubObject(t, i)
		} else {
			data = []byte(strconv.Itoa(i))
		}

		_, err := kinesisClient.PutRecord(ctx, &kinesis.PutRecordInput{
			Data:         data,
			PartitionKey: aws.String(partition),
			StreamName:   aws.String(streamName),
		})
		require.NoError(t, err)
	}
}

func TestMain(m *testing.M) {
	os.Setenv("AWS_ACCESS_KEY_ID", "foobar")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "foobar")

	// delete_streams()
	// create_streams()
	code := m.Run()
	// delete_streams()
	os.Exit(code)
}

func TestBadConfiguration(t *testing.T) {
	cstest.SkipOnWindows(t)
	
	ctx := t.Context()

	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `source: kinesis`,
			expectedErr: "stream_name is mandatory when use_enhanced_fanout is false",
		},
		{
			config: `
source: kinesis
max_retries: whatev`,
			expectedErr: "[3:14] cannot unmarshal string into Go struct field KinesisConfiguration.MaxRetries of type int",
		},
		{
			config: `
source: kinesis
use_enhanced_fanout: true`,
			expectedErr: "stream_arn is mandatory when use_enhanced_fanout is true",
		},
		{
			config: `
source: kinesis
use_enhanced_fanout: true
stream_arn: arn:aws:kinesis:eu-west-1:123456789012:stream/my-stream`,
			expectedErr: "consumer_name is mandatory when use_enhanced_fanout is true",
		},
		{
			config: `
source: kinesis
stream_name: foobar
stream_arn: arn:aws:kinesis:eu-west-1:123456789012:stream/my-stream`,
			expectedErr: "stream_arn and stream_name are mutually exclusive",
		},
	}

	subLogger := log.WithField("type", "kinesis")

	for _, test := range tests {
		t.Run(test.config, func(t *testing.T) {
			f := KinesisSource{}
			err := f.Configure(ctx, []byte(test.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			cstest.AssertErrorContains(t, err, test.expectedErr)
		})
	}
}

func TestReadFromStream(t *testing.T) {
	endpoint := cstest.SetAWSTestEnv(t)

	ctx := t.Context()

	tests := []struct {
		config string
		count  int
		shards int
	}{
		{
			config: `source: kinesis
aws_endpoint: %s
aws_region: us-east-1
stream_name: stream-1-shard`,
			count:  10,
			shards: 1,
		},
	}
	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure(ctx, []byte(config), log.WithField("type", "kinesis"), metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, endpoint, f.Config.StreamName, test.count, test.shards, false)

		for i := range test.count {
			e := <-out
			assert.Equal(t, strconv.Itoa(i), e.Line.Raw)
		}

		tomb.Kill(nil)
		err = tomb.Wait()
		require.NoError(t, err)
	}
}

func TestReadFromMultipleShards(t *testing.T) {
	endpoint := cstest.SetAWSTestEnv(t)

	ctx := t.Context()

	tests := []struct {
		config string
		count  int
		shards int
	}{
		{
			config: `source: kinesis
aws_endpoint: %s
aws_region: us-east-1
stream_name: stream-2-shards`,
			count:  10,
			shards: 2,
		},
	}

	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure(ctx, []byte(config), log.WithField("type", "kinesis"), metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, endpoint, f.Config.StreamName, test.count, test.shards, false)

		c := 0

		for range test.count {
			<-out
			c += 1
		}

		assert.Equal(t, test.count, c)
		tomb.Kill(nil)
		err = tomb.Wait()
		require.NoError(t, err)
	}
}

func TestFromSubscription(t *testing.T) {
	endpoint := cstest.SetAWSTestEnv(t)

	ctx := t.Context()

	tests := []struct {
		config string
		count  int
		shards int
	}{
		{
			config: `source: kinesis
aws_endpoint: %s
aws_region: us-east-1
stream_name: stream-1-shard
from_subscription: true`,
			count:  10,
			shards: 1,
		},
	}

	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure(ctx, []byte(config), log.WithField("type", "kinesis"), metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, endpoint, f.Config.StreamName, test.count, test.shards, true)

		for i := range test.count {
			e := <-out
			assert.Equal(t, strconv.Itoa(i), e.Line.Raw)
		}

		tomb.Kill(nil)
		err = tomb.Wait()
		require.NoError(t, err)
	}
}

/*
func TestSubscribeToStream(t *testing.T) {
	tests := []struct {
		config string
		count  int
		shards int
	}{
		{
			config: `source: kinesis
aws_endpoint: %s
aws_region: us-east-1
stream_arn: arn:aws:kinesis:us-east-1:000000000000:stream/stream-1-shard
consumer_name: consumer-1
use_enhanced_fanout: true`,
			count:  10,
			shards: 1,
		},
	}
	endpoint, _ := getLocalStackEndpoint()
	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure([]byte(config), log.WithField("type", "kinesis"))
		require.NoError(t, err)
		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(out, tomb)
		require.NoError(t, err)
		//Allow the datasource to start listening to the stream
		time.Sleep(10 * time.Second)
		WriteToStream("stream-1-shard", test.count, test.shards)
		for i := 0; i < test.count; i++ {
			e := <-out
			assert.Equal(t, fmt.Sprintf("%d", i), e.Line.Raw)
		}
	}
}
*/
