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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
	SQSName                           string  `yaml:"sqs_name"`
}

type S3Source struct {
	Config     S3Configuration
	logger     *log.Entry
	s3Client   s3iface.S3API
	sqsClient  sqsiface.SQSAPI
	readerChan chan S3Object
	t          *tomb.Tomb
	out        chan types.Event
	ctx        aws.Context
	cancel     context.CancelFunc
}

type S3Object struct {
	Key    string
	Bucket string
}

// For some reason, the aws sdk doesn't have a struct for this
// The one aws-lamdbda-go/events is only intended when using S3 Notification without event bridge
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

var sqsMessagesReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_s3_sqs_messages_total",
		Help: "Number of SQS messages received per queue.",
	},
	[]string{"queue"},
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
			logger.Debugf("Reading file %s/%s", s3Object.Bucket, s3Object.Key)
			err := s.readFile(s3Object.Bucket, s3Object.Key)
			if err != nil {
				logger.Errorf("Error while reading file: %s", err)
			}
		}
	}
}

func (s *S3Source) getBucketContent() ([]*s3.Object, error) {
	logger := s.logger.WithField("method", "getBucketContent")
	logger.Debugf("Getting bucket content for %s", s.Config.BucketName)
	bucketObjects := make([]*s3.Object, 0)
	var continuationToken *string = nil
	for {
		out, err := s.s3Client.ListObjectsV2WithContext(s.ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.Config.BucketName),
			Prefix:            aws.String(s.Config.Prefix),
			ContinuationToken: continuationToken,
		})
		if err != nil {
			logger.Errorf("Error while listing bucket content: %s", err)
			return nil, err
		}
		bucketObjects = append(bucketObjects, out.Contents...)
		if out.NextContinuationToken == nil {
			break
		}
		continuationToken = out.NextContinuationToken
	}
	sort.Slice(bucketObjects, func(i, j int) bool {
		return bucketObjects[i].LastModified.Before(*bucketObjects[j].LastModified)
	})
	return bucketObjects, nil
}

func (s *S3Source) listPoll() error {
	logger := s.logger.WithField("method", "listPoll")
	ticker := time.NewTicker(time.Duration(s.Config.PollingInterval) * time.Second)
	lastObjectDate := time.Now()
	defer ticker.Stop()

	for {
		select {
		case <-s.t.Dying():
			logger.Infof("Shutting down list poller")
			s.cancel()
			return nil
		case <-ticker.C:
			newObject := false
			bucketObjects, err := s.getBucketContent()
			if err != nil {
				logger.Errorf("Error while getting bucket content: %s", err)
				continue
			}
			if bucketObjects == nil {
				continue
			}
			for i := len(bucketObjects) - 1; i >= 0; i-- {
				if bucketObjects[i].LastModified.After(lastObjectDate) {
					newObject = true
					logger.Debugf("Found new object %s", *bucketObjects[i].Key)
					s.readerChan <- S3Object{
						Bucket: s.Config.BucketName,
						Key:    *bucketObjects[i].Key,
					}
				} else {
					break
				}
			}
			if newObject {
				lastObjectDate = *bucketObjects[len(bucketObjects)-1].LastModified
			}
		}
	}
}

func (s *S3Source) extractBucketAndPrefix(message *string) (string, string, error) {
	eventBody := S3Event{}
	err := json.Unmarshal([]byte(*message), &eventBody)
	if err != nil {
		return "", "", err
	}
	if eventBody.Detail.Bucket.Name != "" {
		return eventBody.Detail.Bucket.Name, eventBody.Detail.Object.Key, nil
	}

	s3notifBody := events.S3Event{}
	err = json.Unmarshal([]byte(*message), &s3notifBody)
	if err != nil {
		return "", "", err
	}
	if len(s3notifBody.Records) == 0 {
		return "", "", fmt.Errorf("no records found in S3 notification")
	}
	if !strings.HasPrefix(s3notifBody.Records[0].EventName, "ObjectCreated:") {
		return "", "", fmt.Errorf("event %s is not supported", s3notifBody.Records[0].EventName)
	}
	return s3notifBody.Records[0].S3.Bucket.Name, s3notifBody.Records[0].S3.Object.Key, nil
}

func (s *S3Source) sqsPoll() error {
	logger := s.logger.WithField("method", "sqsPoll").WithField("queue", s.Config.SQSName)
	for {
		select {
		case <-s.t.Dying():
			logger.Infof("Shutting down SQS poller")
			s.cancel()
			return nil
		default:
			logger.Trace("Polling SQS queue")
			out, err := s.sqsClient.ReceiveMessageWithContext(s.ctx, &sqs.ReceiveMessageInput{
				QueueUrl:            aws.String(s.Config.SQSName),
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
				sqsMessagesReceived.WithLabelValues(s.Config.SQSName).Inc()
				bucket, key, err := s.extractBucketAndPrefix(message.Body)
				if err != nil {
					logger.Errorf("Error while parsing SQS message: %s", err)
					//Always delete the message to avoid infinite loop
					_, err = s.sqsClient.DeleteMessage(&sqs.DeleteMessageInput{
						QueueUrl:      aws.String(s.Config.SQSName),
						ReceiptHandle: message.ReceiptHandle,
					})
					if err != nil {
						logger.Errorf("Error while deleting SQS message: %s", err)
					}
					continue
				}
				logger.Debugf("Received SQS message for object %s/%s", bucket, key)
				s.readerChan <- S3Object{Key: key, Bucket: bucket}
				_, err = s.sqsClient.DeleteMessage(&sqs.DeleteMessageInput{
					QueueUrl:      aws.String(s.Config.SQSName),
					ReceiptHandle: message.ReceiptHandle,
				})
				if err != nil {
					logger.Errorf("Error while deleting SQS message: %s", err)
				}
				logger.Debugf("Deleted SQS message for object %s/%s", bucket, key)
			}
		}
	}
}

func (s *S3Source) readFile(bucket string, key string) error {
	//TODO: Handle SSE-C
	var scanner *bufio.Scanner
	output, err := s.s3Client.GetObjectWithContext(s.ctx, &s3.GetObjectInput{
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
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
		} else {
			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
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
	return []prometheus.Collector{linesRead, objectsRead, sqsMessagesReceived}
}
func (s *S3Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead, objectsRead, sqsMessagesReceived}
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

	if s.Config.PollingMethod == PollMethodSQS && s.Config.SQSName == "" {
		return fmt.Errorf("sqs_name is required when using sqs polling method")
	}

	if s.Config.BucketName == "" && s.Config.PollingMethod == PollMethodList {
		return fmt.Errorf("bucket_name is required")
	}

	return nil
}

func (s *S3Source) Configure(yamlConfig []byte, logger *log.Entry) error {
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.logger = logger.WithFields(log.Fields{
		"bucket": s.Config.BucketName,
		"prefix": s.Config.Prefix,
	})

	if !s.Config.UseTimeMachine {
		s.logger.Warning("use_time_machine is not set to true in the datasource configuration. This will likely lead to false positives as S3 logs are not processed in real time.")
	}

	if s.Config.PollingMethod == PollMethodList {
		s.logger.Warning("Polling method is set to list. This is not recommended as it will not scale well. Consider using SQS instead.")
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

	s.logger = logger.WithFields(log.Fields{
		"bucket": s.Config.BucketName,
		"prefix": s.Config.Prefix,
	})

	dsn = strings.TrimPrefix(dsn, "s3://")
	args := strings.Split(dsn, "?")
	if len(args[0]) == 0 {
		return fmt.Errorf("empty s3:// DSN")
	}

	if len(args) == 2 && len(args[1]) != 0 {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return errors.Wrap(err, "could not parse s3 args")
		}
		for key, value := range params {
			if key != "log_level" {
				return fmt.Errorf("unsupported key %s in s3 DSN", key)
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
	if len(pathParts) == 1 {
		s.Config.BucketName = pathParts[0]
		s.Config.Prefix = ""
	} else if len(pathParts) > 1 {
		s.Config.BucketName = pathParts[0]
		if args[0][len(args[0])-1] == '/' {
			s.Config.Prefix = strings.Join(pathParts[1:], "/")
		} else {
			s.Config.Key = strings.Join(pathParts[1:], "/")
		}
	} else {
		return fmt.Errorf("invalid DSN %s for S3 source", dsn)
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
	s.logger.Infof("starting acquisition of %s/%s/%s", s.Config.BucketName, s.Config.Prefix, s.Config.Key)
	s.out = out
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if s.Config.Key != "" {
		err := s.readFile(s.Config.BucketName, s.Config.Key)
		if err != nil {
			return err
		}
	} else {
		//No key, get everything in the bucket based on the prefix
		objects, err := s.getBucketContent()
		if err != nil {
			return err
		}
		for _, object := range objects {
			err := s.readFile(s.Config.BucketName, *object.Key)
			if err != nil {
				return err
			}
		}
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
