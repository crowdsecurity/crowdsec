package s3acquisition

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func TestBadConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "no bucket",
			config: `
source: s3
`,
			expectedErr: "bucket_name is required",
		},
		{
			name: "invalid polling method",
			config: `
source: s3
bucket_name: foobar
polling_method: foobar
`,
			expectedErr: "invalid polling method foobar",
		},
		{
			name: "no sqs name",
			config: `
source: s3
bucket_name: foobar
polling_method: sqs
`,
			expectedErr: "sqs_name is required when using sqs polling method",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := S3Source{}
			err := f.Configure([]byte(test.config), nil)
			if err == nil {
				t.Fatalf("expected error, got none")
			}
			if err.Error() != test.expectedErr {
				t.Fatalf("expected error %s, got %s", test.expectedErr, err.Error())
			}
		})
	}
}

func TestGoodConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "basic",
			config: `
source: s3
bucket_name: foobar
`,
		},
		{
			name: "polling method",
			config: `
source: s3
bucket_name: foobar
polling_method: sqs
sqs_name: foobar
`,
		},
		{
			name: "list method",
			config: `
source: s3
bucket_name: foobar
polling_method: list
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := S3Source{}
			logger := log.NewEntry(log.New())
			err := f.Configure([]byte(test.config), logger)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
		})
	}
}

type mockS3Client struct {
	s3iface.S3API
}

// We add one hour to trick the listing goroutine into thinking the files are new
var mockListOutput map[string][]*s3.Object = map[string][]*s3.Object{
	"bucket_no_prefix": {
		{
			Key:          aws.String("foo.log"),
			LastModified: aws.Time(time.Now().Add(time.Hour)),
		},
	},
	"bucket_with_prefix": {
		{
			Key:          aws.String("prefix/foo.log"),
			LastModified: aws.Time(time.Now().Add(time.Hour)),
		},
		{
			Key:          aws.String("prefix/bar.log"),
			LastModified: aws.Time(time.Now().Add(time.Hour)),
		},
	},
}

func (m mockS3Client) ListObjectsV2WithContext(ctx context.Context, input *s3.ListObjectsV2Input, options ...request.Option) (*s3.ListObjectsV2Output, error) {
	log.Infof("returning mock list output for %s, %v", *input.Bucket, mockListOutput[*input.Bucket])
	return &s3.ListObjectsV2Output{
		Contents: mockListOutput[*input.Bucket],
	}, nil
}

func (m mockS3Client) GetObjectWithContext(ctx context.Context, input *s3.GetObjectInput, options ...request.Option) (*s3.GetObjectOutput, error) {
	r := strings.NewReader("foo\nbar")
	return &s3.GetObjectOutput{
		Body: aws.ReadSeekCloser(r),
	}, nil
}

type mockSQSClient struct {
	sqsiface.SQSAPI
	counter *int32
}

func (msqs mockSQSClient) ReceiveMessageWithContext(ctx context.Context, input *sqs.ReceiveMessageInput, options ...request.Option) (*sqs.ReceiveMessageOutput, error) {
	if atomic.LoadInt32(msqs.counter) == 1 {
		return &sqs.ReceiveMessageOutput{}, nil
	}
	atomic.AddInt32(msqs.counter, 1)
	return &sqs.ReceiveMessageOutput{
		Messages: []*sqs.Message{
			{
				Body: aws.String(`
{"version":"0","id":"af1ce7ea-bdb4-5bb7-3af2-c6cb32f9aac9","detail-type":"Object Created","source":"aws.s3","account":"1234","time":"2023-03-17T07:45:04Z","region":"eu-west-1","resources":["arn:aws:s3:::my_bucket"],"detail":{"version":"0","bucket":{"name":"my_bucket"},"object":{"key":"foo.log","size":663,"etag":"f2d5268a0776d6cdd6e14fcfba96d1cd","sequencer":"0064141A8022966874"},"request-id":"MBWX2P6FWA3S1YH5","requester":"156460612806","source-ip-address":"42.42.42.42","reason":"PutObject"}}`),
			},
		},
	}, nil
}

func (msqs mockSQSClient) DeleteMessage(input *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error) {
	return &sqs.DeleteMessageOutput{}, nil
}

func TestDSNAcquis(t *testing.T) {
	tests := []struct {
		name               string
		dsn                string
		expectedBucketName string
		expectedPrefix     string
		expectedCount      int
	}{
		{
			name:               "basic",
			dsn:                "s3://bucket_no_prefix/foo.log",
			expectedBucketName: "bucket_no_prefix",
			expectedPrefix:     "",
			expectedCount:      2,
		},
		{
			name:               "with prefix",
			dsn:                "s3://bucket_with_prefix/prefix/",
			expectedBucketName: "bucket_with_prefix",
			expectedPrefix:     "prefix/",
			expectedCount:      4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linesRead := 0
			f := S3Source{}
			logger := log.NewEntry(log.New())
			err := f.ConfigureByDSN(test.dsn, map[string]string{"foo": "bar"}, logger)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			assert.Equal(t, test.expectedBucketName, f.Config.BucketName)
			assert.Equal(t, test.expectedPrefix, f.Config.Prefix)
			out := make(chan types.Event)

			done := make(chan bool)

			go func() {
				for {
					select {
					case s := <-out:
						fmt.Printf("got line %s\n", s.Line.Raw)
						linesRead++
					case <-done:
						return
					}
				}
			}()

			f.s3Client = mockS3Client{}
			err = f.OneShotAcquisition(out, nil)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			time.Sleep(2 * time.Second)
			done <- true
			assert.Equal(t, test.expectedCount, linesRead)

		})
	}

}

func TestListPolling(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedCount int
	}{
		{
			name: "basic",
			config: `
source: s3
bucket_name: bucket_no_prefix
polling_method: list
polling_interval: 1
`,
			expectedCount: 2,
		},
		{
			name: "with prefix",
			config: `
source: s3
bucket_name: bucket_with_prefix
polling_method: list
polling_interval: 1
prefix: foo/
`,
			expectedCount: 4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linesRead := 0
			f := S3Source{}
			logger := log.NewEntry(log.New())
			logger.Logger.SetLevel(log.TraceLevel)
			err := f.Configure([]byte(test.config), logger)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if f.Config.PollingMethod != PollMethodList {
				t.Fatalf("expected list polling, got %s", f.Config.PollingMethod)
			}

			f.s3Client = mockS3Client{}

			out := make(chan types.Event)
			tb := tomb.Tomb{}

			go func() {
				for {
					select {
					case s := <-out:
						fmt.Printf("got line %s\n", s.Line.Raw)
						linesRead++
					case <-tb.Dying():
						return
					}
				}
			}()

			err = f.StreamingAcquisition(out, &tb)

			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			time.Sleep(2 * time.Second)
			tb.Kill(nil)
			err = tb.Wait()
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			assert.Equal(t, test.expectedCount, linesRead)
		})
	}
}

func TestSQSPoll(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedCount int
	}{
		{
			name: "basic",
			config: `
source: s3
bucket_name: bucket_no_prefix
polling_method: sqs
sqs_name: test
`,
			expectedCount: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linesRead := 0
			f := S3Source{}
			logger := log.NewEntry(log.New())
			err := f.Configure([]byte(test.config), logger)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if f.Config.PollingMethod != PollMethodSQS {
				t.Fatalf("expected sqs polling, got %s", f.Config.PollingMethod)
			}

			counter := int32(0)
			f.s3Client = mockS3Client{}
			f.sqsClient = mockSQSClient{counter: &counter}

			out := make(chan types.Event)
			tb := tomb.Tomb{}

			go func() {
				for {
					select {
					case s := <-out:
						fmt.Printf("got line %s\n", s.Line.Raw)
						linesRead++
					case <-tb.Dying():
						return
					}
				}
			}()

			err = f.StreamingAcquisition(out, &tb)

			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			time.Sleep(2 * time.Second)
			tb.Kill(nil)
			err = tb.Wait()
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			assert.Equal(t, test.expectedCount, linesRead)
		})
	}
}
