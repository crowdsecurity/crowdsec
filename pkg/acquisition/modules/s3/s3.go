package s3acquisition

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
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

type S3Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         string  `yaml:"aws_region"`
	AwsEndpoint                       string  `yaml:"aws_endpoint"`
	BucketName                        string  `yaml:"bucket_name"`
	Prefix                            string  `yaml:"prefix"`
	Key                               string  `yaml:"-"` //Only for DSN acquisition
	PollingMethod                     string  `yaml:"polling_method"`
	PollingInterval                   int     `yaml:"polling_interval"`
	SQSARN                            string  `yaml:"sqs_arn"`
}

type S3Source struct {
	Config     S3Configuration
	logger     *log.Entry
	s3Client   *s3.S3
	sqsClient  *sqs.SQS
	readerChan chan S3Object
	t          *tomb.Tomb
	out        chan types.Event
	ctx        aws.Context
	cancel     context.CancelFunc
}

type S3Object struct {
	Key    string
	Bucker string
}

// For some reason, the aws sdk doesn't have a struct for this
// aws-lamdbda-go/events has a similar one, but looks like it's only intended for use with lambda (format is different)
type S3Event struct {
	Version    string   `json:"version"`
	Id         string   `json:"id"`
	DetailType string   `json:"detail-type"`
	Source     string   `json:"source"`
	Account    string   `json:"account"`
	Time       string   `json:"time"`
	Region     string   `json:"region"`
	Resources  []string `json:"resources"`
	Detail     struct {
		Version         string `json:"version"`
		RequestId       string `json:"request-id"`
		Requester       string `json:"requester"`
		Reason          string `json:"reason"`
		SourceIpAddress string `json:"source-ip-address"`
		Bucket          struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key       string `json:"key"`
			Size      int    `json:"size"`
			Etag      string `json:"etag"`
			Sequencer string `json:"sequencer"`
		} `json:"object"`
	} `json:"detail"`
}

const PollMethodList = "list"
const PollMethodSQS = "sqs"

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_s3_hits_total",
		Help: "Number of events read per bucket.",
	},
	[]string{"bucket"},
)

var objectsRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_s3_objects_total",
		Help: "Number of objects read per bucket.",
	},
	[]string{"bucket"},
)

func (s *S3Source) newS3Client() error {
	var sess *session.Session

	if s.Config.AwsProfile != nil {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Profile:           *s.Config.AwsProfile,
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
	if s.Config.AwsRegion != "" {
		config = config.WithRegion(s.Config.AwsRegion)
	}
	if s.Config.AwsEndpoint != "" {
		config = config.WithEndpoint(s.Config.AwsEndpoint)
	}
	s.s3Client = s3.New(sess, config)
	if s.s3Client == nil {
		return fmt.Errorf("failed to create S3 client")
	}
	return nil
}

func (s *S3Source) newSQSClient() error {
	var sess *session.Session

	if s.Config.AwsProfile != nil {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Profile:           *s.Config.AwsProfile,
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
	if s.Config.AwsRegion != "" {
		config = config.WithRegion(s.Config.AwsRegion)
	}
	if s.Config.AwsEndpoint != "" {
		config = config.WithEndpoint(s.Config.AwsEndpoint)
	}
	s.sqsClient = sqs.New(sess, config)
	if s.sqsClient == nil {
		return fmt.Errorf("failed to create SQS client")
	}
	return nil
}

func (s *S3Source) readManager() {
	logger := s.logger.WithField("method", "readManager")
	for {
		select {
		case <-s.t.Dying():
			logger.Infof("Shutting down S3 read manager")
			s.cancel()
			return
		case s3Object := <-s.readerChan:
			logger.Debugf("Reading file %s/%s", s3Object.Bucker, s3Object.Key)
			err := s.readFile(s3Object.Bucker, s3Object.Key)
			if err != nil {
				logger.Errorf("Error while reading file: %s", err)
			}
		}
	}
}

func (s *S3Source) listPoll() error {
	logger := s.logger.WithField("method", "listPoll")
	ticker := time.NewTicker(time.Duration(s.Config.PollingInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.t.Dying():
			logger.Infof("Shutting down list poller")
			s.cancel()
			return nil
		case <-ticker.C:
			bucketObjects := make([]*s3.Object, 0)
			var continuationToken *string = nil
			logger.Debugf("Polling S3 bucket %s", s.Config.BucketName)
			for {
				out, err := s.s3Client.ListObjectsV2WithContext(s.ctx, &s3.ListObjectsV2Input{
					Bucket:            aws.String(s.Config.BucketName),
					MaxKeys:           aws.Int64(1000),
					Prefix:            aws.String(s.Config.Prefix),
					ContinuationToken: continuationToken,
				})
				if err != nil {
					logger.Errorf("Error while polling S3: %s", err)
					break
				}
				bucketObjects = append(bucketObjects, out.Contents...)
				if out.ContinuationToken != nil {
					continuationToken = out.ContinuationToken
				} else {
					break
				}
			}
			sort.Slice(bucketObjects, func(i, j int) bool {
				return bucketObjects[i].LastModified.Before(*bucketObjects[j].LastModified)
			})
			spew.Dump(bucketObjects)
		}
	}
}

func (s *S3Source) sqsPoll() error {
	logger := s.logger.WithField("method", "sqsPoll")
	for {
		select {
		case <-s.t.Dying():
			logger.Infof("Shutting down SQS poller")
			s.cancel()
			return nil
		default:
			logger.Tracef("Polling SQS queue %s", s.Config.SQSARN)
			out, err := s.sqsClient.ReceiveMessageWithContext(s.ctx, &sqs.ReceiveMessageInput{
				QueueUrl:            aws.String(s.Config.SQSARN),
				MaxNumberOfMessages: aws.Int64(10),
				WaitTimeSeconds:     aws.Int64(20), //Probably no need to make it configurable ?
			})
			if err != nil {
				logger.Errorf("Error while polling SQS: %s", err)
				continue
			}
			logger.Tracef("SQS output: %v", out)
			logger.Debugf("Received %d messages from SQS", len(out.Messages))
			for _, message := range out.Messages {
				eventBody := S3Event{}
				err := json.Unmarshal([]byte(*message.Body), &eventBody)
				if err != nil {
					logger.Errorf("Error while parsing SQS message: %s", err)
					continue
				}
				logger.Tracef("S3 event body: %v", eventBody)
				logger.Debugf("Received SQS message for object %s/%s", eventBody.Detail.Bucket.Name, eventBody.Detail.Object.Key)
				s.readerChan <- S3Object{Key: eventBody.Detail.Object.Key, Bucker: eventBody.Detail.Bucket.Name}
				_, err = s.sqsClient.DeleteMessage(&sqs.DeleteMessageInput{
					QueueUrl:      aws.String(s.Config.SQSARN),
					ReceiptHandle: message.ReceiptHandle,
				})
				if err != nil {
					logger.Errorf("Error while deleting SQS message: %s", err)
				}
				logger.Debugf("Deleted SQS message for object %s/%s", eventBody.Detail.Bucket.Name, eventBody.Detail.Object.Key)
			}
			//time.Sleep(time.Duration(s.Config.PollingInterval) * time.Second)
		}
	}
}

func (s *S3Source) readFile(bucket string, key string) error {
	//TODO: Handle SSE
	var scanner *bufio.Scanner
	output, err := s.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to get object %s/%s: %w", bucket, key, err)
	}
	defer output.Body.Close()
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(output.Body)
		if err != nil {
			return fmt.Errorf("failed to read gzip object %s/%s: %w", bucket, key, err)
		}
		defer gzReader.Close()
		scanner = bufio.NewScanner(gzReader)
	} else {
		scanner = bufio.NewScanner(output.Body)
	}
	for scanner.Scan() {
		text := scanner.Text()
		s.logger.Tracef("Read line %s", text)
		linesRead.WithLabelValues(bucket).Inc()
		l := types.Line{}
		l.Raw = text
		l.Labels = s.Config.Labels
		l.Time = time.Now().UTC()
		l.Process = true
		l.Module = s.GetName()
		l.Src = bucket
		var evt types.Event
		if !s.Config.UseTimeMachine {
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leakybucket.LIVE}
		} else {
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leakybucket.TIMEMACHINE}
		}
		s.out <- evt
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read object %s/%s: %s", bucket, key, err)
	}
	objectsRead.WithLabelValues(bucket).Inc()
	return nil
}

func (s *S3Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead, objectsRead}
}
func (s *S3Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead, objectsRead}
}

func (s *S3Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = S3Configuration{}
	err := yaml.UnmarshalStrict(yamlConfig, &s.Config)
	if err != nil {
		return fmt.Errorf("cannot parse S3Acquisition configuration: %w", err)
	}
	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}
	if s.Config.PollingMethod == "" {
		s.Config.PollingMethod = PollMethodList
	}

	if s.Config.PollingInterval == 0 {
		s.Config.PollingInterval = 60
	}

	if s.Config.PollingMethod != PollMethodList && s.Config.PollingMethod != PollMethodSQS {
		return fmt.Errorf("invalid polling method %s", s.Config.PollingMethod)
	}

	if s.Config.PollingMethod == PollMethodSQS && s.Config.SQSARN == "" {
		return fmt.Errorf("sqs_arn is required when using sqs polling method")
	}

	if s.Config.BucketName == "" && s.Config.PollingMethod == PollMethodList {
		return fmt.Errorf("bucket_name is required")
	}

	return nil
}

func (s *S3Source) Configure(yamlConfig []byte, logger *log.Entry) error {
	s.logger = logger
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}
	err = s.newS3Client()
	if err != nil {
		return err
	}

	if s.Config.PollingMethod == PollMethodSQS {
		err = s.newSQSClient()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *S3Source) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	if !strings.HasPrefix(dsn, "s3://") {
		return fmt.Errorf("invalid DSN %s for S3 source, must start with s3://", dsn)
	}

	s.logger = logger

	dsn = strings.TrimPrefix(dsn, "s3://")
	args := strings.Split(dsn, "?")
	if len(args[0]) == 0 {
		return fmt.Errorf("empty s3:// DSN")
	}

	if len(args) == 2 && len(args[1]) != 0 {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return errors.Wrap(err, "could not parse file args")
		}
		for key, value := range params {
			if key != "log_level" {
				return fmt.Errorf("unsupported key %s in file DSN", key)
			}
			if len(value) != 1 {
				return errors.New("expected zero or one value for 'log_level'")
			}
			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", value[0])
			}
			s.logger.Logger.SetLevel(lvl)
		}
	}

	s.Config = S3Configuration{}
	s.Config.Labels = labels
	s.Config.Mode = configuration.CAT_MODE

	pathParts := strings.Split(args[0], "/")
	s.logger.Debugf("pathParts: %v", pathParts)

	//FIXME: handle s3://bucket/
	if len(pathParts) < 2 {
		return fmt.Errorf("invalid DSN %s for S3 source, must be s3://bucket/key", dsn)
	}

	s.Config.BucketName = pathParts[0]
	if args[0][len(args[0])-1] == '/' {
		s.Config.Prefix = strings.Join(pathParts[1:], "/")
	} else {
		s.Config.Key = strings.Join(pathParts[1:], "/")
	}

	err := s.newS3Client()
	if err != nil {
		return err
	}

	return nil
}

func (s *S3Source) GetMode() string {
	return s.Config.Mode
}

func (s *S3Source) GetName() string {
	return "s3"
}

func (s *S3Source) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	s.logger.Infof("starting acquisition of %s/%s", s.Config.BucketName, s.Config.Key)
	s.out = out
	//TODO: handle being passed a prefix, and iterate over all keys
	if s.Config.Key != "" {
		err := s.readFile(s.Config.BucketName, s.Config.Key)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("key is required")
	}
	return nil
}

func (s *S3Source) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	s.t = t
	s.out = out
	s.readerChan = make(chan S3Object, 100) //FIXME: does this needs to be buffered?
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.logger.Infof("starting acquisition of %s/%s", s.Config.BucketName, s.Config.Prefix)
	t.Go(func() error {
		s.readManager()
		return nil
	})
	if s.Config.PollingMethod == PollMethodSQS {
		t.Go(func() error {
			err := s.sqsPoll()
			if err != nil {
				return err
			}
			return nil
		})
	} else {
		t.Go(func() error {
			err := s.listPoll()
			if err != nil {
				return err
			}
			return nil
		})
	}
	return nil
}

func (s *S3Source) CanRun() error {
	return nil
}

func (s *S3Source) Dump() interface{} {
	return s
}
