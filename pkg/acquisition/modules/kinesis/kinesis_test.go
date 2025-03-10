package kinesisacquisition

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func getLocalStackEndpoint() (string, error) {
	endpoint := "http://localhost:4566"

	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		v = strings.TrimPrefix(v, "http://")

		_, err := net.Dial("tcp", v)
		if err != nil {
			return "", fmt.Errorf("while dialing %s: %w: aws endpoint isn't available", v, err)
		}
	}

	return endpoint, nil
}

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

func WriteToStream(t *testing.T, streamName string, count int, shards int, sub bool) {
	endpoint, err := getLocalStackEndpoint()
	require.NoError(t, err)

	sess := session.Must(session.NewSession())
	kinesisClient := kinesis.New(sess, aws.NewConfig().WithEndpoint(endpoint).WithRegion("us-east-1"))

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

		_, err = kinesisClient.PutRecord(&kinesis.PutRecordInput{
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
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

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
		f := KinesisSource{}
		err := f.Configure([]byte(test.config), subLogger, configuration.METRICS_NONE)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestReadFromStream(t *testing.T) {
	ctx := t.Context()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

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
	endpoint, _ := getLocalStackEndpoint()

	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure([]byte(config), log.WithField("type", "kinesis"), configuration.METRICS_NONE)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, f.Config.StreamName, test.count, test.shards, false)

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
	ctx := t.Context()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

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
	endpoint, _ := getLocalStackEndpoint()

	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure([]byte(config), log.WithField("type", "kinesis"), configuration.METRICS_NONE)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, f.Config.StreamName, test.count, test.shards, false)

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
	ctx := t.Context()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

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
	endpoint, _ := getLocalStackEndpoint()

	for _, test := range tests {
		f := KinesisSource{}
		config := fmt.Sprintf(test.config, endpoint)
		err := f.Configure([]byte(config), log.WithField("type", "kinesis"), configuration.METRICS_NONE)
		require.NoError(t, err)

		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(ctx, out, tomb)
		require.NoError(t, err)
		// Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(t, f.Config.StreamName, test.count, test.shards, true)

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
