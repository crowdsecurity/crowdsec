package s3acquisition

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestBadConfiguration(t *testing.T) {
	ctx := t.Context()

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
			name: "type mismatch",
			config: `
source: s3
max_buffer_size: true
`,
			expectedErr: "[3:18] cannot unmarshal bool into Go struct field S3Configuration.MaxBufferSize of type int",
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
		{
			name: "both bucket and sqs",
			config: `
source: s3
bucket_name: foobar
polling_method: sqs
sqs_name: foobar
`,
			expectedErr: "bucket_name and sqs_name are mutually exclusive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := S3Source{}

			err := f.Configure(ctx, []byte(test.config), nil, metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, test.expectedErr)
		})
	}
}

func TestGoodConfiguration(t *testing.T) {
	ctx := t.Context()

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

			err := f.Configure(ctx, []byte(test.config), logger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)
		})
	}
}

type mockS3Client struct{}

// We add one hour to trick the listing goroutine into thinking the files are new
var mockListOutput map[string][]s3types.Object = map[string][]s3types.Object{
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

func (mockS3Client) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	log.Infof("returning mock list output for %s, %v", *input.Bucket, mockListOutput[*input.Bucket])

	return &s3.ListObjectsV2Output{
		Contents: mockListOutput[*input.Bucket],
	}, nil
}

func (mockS3Client) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	r := strings.NewReader("foo\nbar")
	return &s3.GetObjectOutput{Body: io.NopCloser(r)}, nil
}

type mockSQSClient struct {
	counter *int32
}

func (msqs mockSQSClient) ReceiveMessage(_ context.Context, _ *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	if atomic.LoadInt32(msqs.counter) == 1 {
		return &sqs.ReceiveMessageOutput{}, nil
	}

	atomic.AddInt32(msqs.counter, 1)

	return &sqs.ReceiveMessageOutput{
		Messages: []sqstypes.Message{
			{
				Body: aws.String(`
{"version":"0","id":"af1ce7ea-bdb4-5bb7-3af2-c6cb32f9aac9","detail-type":"Object Created","source":"aws.s3","account":"1234","time":"2023-03-17T07:45:04Z","region":"eu-west-1","resources":["arn:aws:s3:::my_bucket"],"detail":{"version":"0","bucket":{"name":"my_bucket"},"object":{"key":"foo.log","size":663,"etag":"f2d5268a0776d6cdd6e14fcfba96d1cd","sequencer":"0064141A8022966874"},"request-id":"MBWX2P6FWA3S1YH5","requester":"156460612806","source-ip-address":"42.42.42.42","reason":"PutObject"}}`),
			},
		},
	}, nil
}

func (mockSQSClient) DeleteMessage(_ context.Context, _ *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	return &sqs.DeleteMessageOutput{}, nil
}

type mockSQSClientNotif struct {
	counter *int32
}

func (msqs mockSQSClientNotif) ReceiveMessage(_ context.Context, _ *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	if atomic.LoadInt32(msqs.counter) == 1 {
		return &sqs.ReceiveMessageOutput{}, nil
	}

	atomic.AddInt32(msqs.counter, 1)

	return &sqs.ReceiveMessageOutput{
		Messages: []sqstypes.Message{
			{
				Body: aws.String(`
				{"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"eu-west-1","eventTime":"2023-03-20T19:30:02.536Z","eventName":"ObjectCreated:Put","userIdentity":{"principalId":"AWS:XXXXX"},"requestParameters":{"sourceIPAddress":"42.42.42.42"},"responseElements":{"x-amz-request-id":"FM0TAV2WE5AXXW42","x-amz-id-2":"LCfQt1aSBtD1G5wdXjB5ANdPxLEXJxA89Ev+/rRAsCGFNJGI/1+HMlKI59S92lqvzfViWh7B74leGKWB8/nNbsbKbK7WXKz2"},"s3":{"s3SchemaVersion":"1.0","configurationId":"test-acquis","bucket":{"name":"my_bucket","ownerIdentity":{"principalId":"A1F2PSER1FB8MY"},"arn":"arn:aws:s3:::my_bucket"},"object":{"key":"foo.log","size":3097,"eTag":"ab6889744611c77991cbc6ca12d1ddc7","sequencer":"006418B43A76BC0257"}}}]}`),
			},
		},
	}, nil
}

func (mockSQSClientNotif) DeleteMessage(_ context.Context, _ *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	return &sqs.DeleteMessageOutput{}, nil
}

type mockSQSClientSNS struct {
	counter *int32
}

func (msqs mockSQSClientSNS) ReceiveMessage(_ context.Context, _ *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	if atomic.LoadInt32(msqs.counter) == 1 {
		return &sqs.ReceiveMessageOutput{}, nil
	}

	atomic.AddInt32(msqs.counter, 1)

	return &sqs.ReceiveMessageOutput{
		Messages: []sqstypes.Message{
			{
				Body: aws.String(`
				{"Type":"Notification","MessageId":"95f3b5d2-c347-577e-b07d-d535ff80d9c4","TopicArn":"arn:aws:sns:eu-west-1:309081560286:s3-notif","Subject":"Amazon S3 Notification","Message":"{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"eu-west-1\",\"eventTime\":\"2025-07-08T15:34:31.272Z\",\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AWS:xxx:xxx@crowdsec.net\"},\"requestParameters\":{\"sourceIPAddress\":\"1.1.1.1\"},\"responseElements\":{\"x-amz-request-id\":\"F8PK5SP9MC5R76F5\",\"x-amz-id-2\":\"dEZVAhJ9ufBn3ufcJH8wzRw2bfiwGzqaq4iQ9rYKkScQ3o4fGjbqe4dWCAPNwc1khCVKRSbfRwD9HXgDElOHcZazOIBxVY1l\"},\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"test\",\"bucket\":{\"name\":\"my_bucket\",\"ownerIdentity\":{\"principalId\":\"A2BHZN7P6G2N16\"},\"arn\":\"arn:aws:s3:::my_bucket\"},\"object\":{\"key\":\"foo.log\",\"size\":3,\"eTag\":\"50a2fabfdd276f573ff97ace8b11c5f4\",\"sequencer\":\"00686D3A8738EE3CA0\"}}}]}","Timestamp":"2025-07-08T15:34:31.803Z","SignatureVersion":"1","Signature":"lkkFr7lYAUEBl6CPPDUDg1D1/zRToR2a9M1MnAmzC8pN33VQf1m+lUQJAgAOKUNxHfIUx1grFyxFQa+84/+edpE4tdhwr0bJ3QELlmJd0xot2pdoc2syrBC1Yq/3IsGc3ZIIIyyG9FXW0Q60aQeZAkx9XQC0tUQDwc8d3kef8CzN5i+ys3QXtX+7KUzj1tNoWQSCcjzqid3JSSyJzRZRD1/0Zkvnd3XVBXaM/QTtin1/Ja8uEObHw9AOy+oi/CygjREBaRzYUBdQHY7/kiA1sdDiSqkyEZ0uSu36aA8A4LO1O6ltP/h4avN8LARmgkdcVbGoPKZIu6Xe5tYvOdJKeA==","SigningCertURL":"https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-9c6465fa7f48f5cacd23014631ec1136.pem","UnsubscribeURL":"https://sns.eu-west-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:eu-west-1:309081560286:s3-notif:acfdadc0-43d0-48ba-81c9-052bd253febe"}
				`),
			},
		},
	}, nil
}

func (mockSQSClientSNS) DeleteMessage(_ context.Context, _ *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	return &sqs.DeleteMessageOutput{}, nil
}

func TestDSNAcquis(t *testing.T) {
	ctx := t.Context()
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
			err := f.ConfigureByDSN(ctx, test.dsn, map[string]string{"foo": "bar"}, logger, "")
			require.NoError(t, err)

			f.s3Client = mockS3Client{}

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

			tmb := tomb.Tomb{}
			err = f.OneShotAcquisition(ctx, out, &tmb)
			require.NoError(t, err)
			time.Sleep(2 * time.Second)

			done <- true

			assert.Equal(t, test.expectedCount, linesRead)
		})
	}
}

func TestListPolling(t *testing.T) {
	ctx := t.Context()
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

			err := f.Configure(ctx, []byte(test.config), logger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			f.s3Client = mockS3Client{}

			if f.Config.PollingMethod != PollMethodList {
				t.Fatalf("expected list polling, got %s", f.Config.PollingMethod)
			}

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

			err = f.StreamingAcquisition(ctx, out, &tb)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			time.Sleep(2 * time.Second)
			tb.Kill(nil)
			err = tb.Wait()
			require.NoError(t, err)
			assert.Equal(t, test.expectedCount, linesRead)
		})
	}
}

func TestSQSPoll(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		config        string
		notifType     string
		expectedCount int
	}{
		{
			name: "eventbridge",
			config: `
source: s3
polling_method: sqs
sqs_name: test
`,
			expectedCount: 2,
			notifType:     SQSFormatEventBridge,
		},
		{
			name: "notification",
			config: `
source: s3
polling_method: sqs
sqs_name: test
`,
			expectedCount: 2,
			notifType:     SQSFormatS3Notification,
		},
		{
			name: "sns",
			config: `
source: s3
polling_method: sqs
sqs_name: test
`,
			expectedCount: 2,
			notifType:     SQSFormatSNS,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linesRead := 0
			f := S3Source{}
			logger := log.NewEntry(log.New())
			err := f.Configure(ctx, []byte(test.config), logger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			f.s3Client = mockS3Client{}

			if f.Config.PollingMethod != PollMethodSQS {
				t.Fatalf("expected sqs polling, got %s", f.Config.PollingMethod)
			}

			counter := int32(0)

			switch test.notifType {
			case SQSFormatEventBridge:
				f.sqsClient = mockSQSClient{counter: &counter}
			case SQSFormatS3Notification:
				f.sqsClient = mockSQSClientNotif{counter: &counter}
			case SQSFormatSNS:
				f.sqsClient = mockSQSClientSNS{counter: &counter}
			default:
				t.Fatalf("unknown notification type %s", test.notifType)
			}

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

			err = f.StreamingAcquisition(ctx, out, &tb)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			time.Sleep(2 * time.Second)
			tb.Kill(nil)

			err = tb.Wait()
			require.NoError(t, err)
			assert.Equal(t, test.expectedCount, linesRead)
		})
	}
}
