package s3acquisition

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
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

func (m mockS3Client) ListObjectsV2WithContext(ctx context.Context, input *s3.ListObjectsV2Input, options ...request.Option) (*s3.ListObjectsV2Output, error) {
	return &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			{
				Key:          aws.String("foo.log"),
				LastModified: aws.Time(time.Now()),
			},
		},
	}, nil
}

func (m mockS3Client) GetObjectWithContext(ctx context.Context, input *s3.GetObjectInput, options ...request.Option) (*s3.GetObjectOutput, error) {
	r := strings.NewReader("foo\nbar")
	return &s3.GetObjectOutput{
		Body: aws.ReadSeekCloser(r),
	}, nil
}

func TestListPolling(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "basic",
			config: `
source: s3
bucket_name: foobar
polling_method: list
polling_interval: 1
`,
		},
		{
			name: "with prefix",
			config: `
source: s3
bucket_name: foobar
polling_method: list
polling_interval: 1
prefix: foo/
`,
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
			assert.Equal(t, 2, linesRead)
		})
	}

}
