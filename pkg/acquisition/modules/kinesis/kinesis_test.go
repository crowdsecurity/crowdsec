package kinesisacquisition

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func getLocalStackEndpoint() (string, error) {
	endpoint := "http://localhost:4566"
	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		v = strings.TrimPrefix(v, "http://")
		_, err := net.Dial("tcp", v)
		if err != nil {
			return "", fmt.Errorf("while dialing %s : %s : aws endpoint isn't available", v, err)
		}
	}
	return endpoint, nil
}

func createAndWaitForStream(streamName string, shards int64) {
	endpoint, err := getLocalStackEndpoint()
	if err != nil {
		log.Fatal(err)
	}
	sess := session.Must(session.NewSession())
	kinesisClient := kinesis.New(sess, aws.NewConfig().WithEndpoint(endpoint).WithRegion("us-east-1"))
	_, err = kinesisClient.CreateStream(&kinesis.CreateStreamInput{
		ShardCount: aws.Int64(shards),
		StreamName: aws.String(streamName),
	})
	if err != nil {
		fmt.Printf("Error creating stream: %s\n", err)
		log.Fatal(err)
	}
	fmt.Printf("Waiting for stream %s to be created\n", streamName)
	/*	for {
		a, err := kinesisClient.DescribeStream(&kinesis.DescribeStreamInput{
			StreamName: aws.String(streamName),
		})
		if err != nil {
			fmt.Printf("Error describing stream: %s\n", err)
			log.Fatal(err)
		}
		spew.Dump(a)
	}*/
	kinesisClient.WaitUntilStreamExists(&kinesis.DescribeStreamInput{
		StreamName: aws.String(streamName),
	})
}

func deleteAndWaitForStream(streamName string) {
	fmt.Printf("Waiting for stream %s to be deleted\n", streamName)
	endpoint, err := getLocalStackEndpoint()
	if err != nil {
		log.Fatal(err)
	}
	sess := session.Must(session.NewSession())
	kinesisClient := kinesis.New(sess, aws.NewConfig().WithEndpoint(endpoint).WithRegion("us-east-1"))
	_, err = kinesisClient.DeleteStream(&kinesis.DeleteStreamInput{
		StreamName: aws.String(streamName),
	})
	if err != nil {
		switch err.(type) {
		case *kinesis.ResourceNotFoundException:
			return
		default:
			fmt.Printf("Error deleting stream: %s\n", err)
			return
		}
	}
	kinesisClient.WaitUntilStreamNotExists(&kinesis.DescribeStreamInput{
		StreamName: aws.String(streamName),
	})
}

func create_streams() {
	createAndWaitForStream("stream-1-shard", 1)
	createAndWaitForStream("stream-2-shards", 2)
}

func delete_streams() {
	deleteAndWaitForStream("stream-1-shard")
	deleteAndWaitForStream("stream-2-shards")
}

func WriteToStream(streamName string, count int, shards int) {
	endpoint, err := getLocalStackEndpoint()
	if err != nil {
		log.Fatal(err)
	}
	sess := session.Must(session.NewSession())
	kinesisClient := kinesis.New(sess, aws.NewConfig().WithEndpoint(endpoint).WithRegion("us-east-1"))
	for i := 0; i < count; i++ {
		partition := "partition"
		if shards != 1 {
			partition = fmt.Sprintf("partition-%d", i%shards)
		}
		_, err = kinesisClient.PutRecord(&kinesis.PutRecordInput{
			Data:         []byte(fmt.Sprintf("%d", i)),
			PartitionKey: aws.String(partition),
			StreamName:   aws.String(streamName),
		})
		if err != nil {
			fmt.Printf("Error writing to stream: %s\n", err)
			log.Fatal(err)
		}
	}
}

func TestMain(m *testing.M) {
	os.Setenv("AWS_ACCESS_KEY_ID", "foobar")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "foobar")

	delete_streams()
	create_streams()
	code := m.Run()
	//delete_streams()
	os.Exit(code)
}

func TestBadConfiguration(t *testing.T) {
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
	}

	subLogger := log.WithFields(log.Fields{
		"type": "kinesis",
	})
	for _, test := range tests {
		f := KinesisSource{}
		err := f.Configure([]byte(test.config), subLogger)
		if test.expectedErr != "" && err == nil {
			t.Fatalf("Expected err %s but got nil !", test.expectedErr)
		}
		if test.expectedErr != "" {
			assert.Contains(t, err.Error(), test.expectedErr)
		}
	}
}

func TestReadFromStream(t *testing.T) {
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
		err := f.Configure([]byte(config), log.WithFields(log.Fields{
			"type": "kinesis",
		}))
		if err != nil {
			t.Fatalf("Error configuring source: %s", err)
		}
		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(out, tomb)
		if err != nil {
			t.Fatalf("Error starting source: %s", err)
		}
		//Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(f.Config.StreamName, test.count, test.shards)
		for i := 0; i < test.count; i++ {
			e := <-out
			assert.Equal(t, fmt.Sprintf("%d", i), e.Line.Raw)
		}
	}
}

func TestReadFromMultipleShards(t *testing.T) {
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
		err := f.Configure([]byte(config), log.WithFields(log.Fields{
			"type": "kinesis",
		}))
		if err != nil {
			t.Fatalf("Error configuring source: %s", err)
		}
		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(out, tomb)
		if err != nil {
			t.Fatalf("Error starting source: %s", err)
		}
		//Allow the datasource to start listening to the stream
		time.Sleep(4 * time.Second)
		WriteToStream(f.Config.StreamName, test.count, test.shards)
		c := 0
		for i := 0; i < test.count; i++ {
			<-out
			c += 1
		}
		assert.Equal(t, test.count, c)
	}
}

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
		err := f.Configure([]byte(config), log.WithFields(log.Fields{
			"type": "kinesis",
		}))
		if err != nil {
			t.Fatalf("Error configuring source: %s", err)
		}
		tomb := &tomb.Tomb{}
		out := make(chan types.Event)
		err = f.StreamingAcquisition(out, tomb)
		if err != nil {
			t.Fatalf("Error starting source: %s", err)
		}
		//Allow the datasource to start listening to the stream
		time.Sleep(10 * time.Second)
		WriteToStream("stream-1-shard", test.count, test.shards)
		for i := 0; i < test.count; i++ {
			e := <-out
			assert.Equal(t, fmt.Sprintf("%d", i), e.Line.Raw)
		}
	}
}
