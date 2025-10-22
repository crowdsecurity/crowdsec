package s3acquisition

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type S3API interface {
	s3Manager.ListObjectsV2APIClient
	s3Manager.DownloadAPIClient
}

type SQSAPI interface {
	ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, params *sqs.DeleteMessageInput, optFns ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type S3Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         string  `yaml:"aws_region"`
	AwsEndpoint                       string  `yaml:"aws_endpoint"`
	BucketName                        string  `yaml:"bucket_name"`
	Prefix                            string  `yaml:"prefix"`
	Key                               string  `yaml:"-"` // Only for DSN acquisition
	PollingMethod                     string  `yaml:"polling_method"`
	PollingInterval                   int     `yaml:"polling_interval"`
	SQSName                           string  `yaml:"sqs_name"`
	SQSFormat                         string  `yaml:"sqs_format"`
	MaxBufferSize                     int     `yaml:"max_buffer_size"`
}

type S3Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       S3Configuration
	logger       *log.Entry
	s3Client     S3API
	sqsClient    SQSAPI
	readerChan   chan S3Object
	t            *tomb.Tomb
	out          chan types.Event
	ctx          context.Context
	cancel       context.CancelFunc
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

// For events that are published to SQS by SNS
// We only care about the message itself, the other SNS metadata are not needed
type SNSEvent struct {
	Message string `json:"Message"`
}

const (
	PollMethodList          = "list"
	PollMethodSQS           = "sqs"
	SQSFormatEventBridge    = "eventbridge"
	SQSFormatS3Notification = "s3notification"
	SQSFormatSNS            = "sns"
)

func (s *S3Source) newS3Client(ctx context.Context) (*s3.Client, error) {
	var loadOpts []func(*config.LoadOptions) error
	if s.Config.AwsProfile != nil && *s.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*s.Config.AwsProfile))
	}

	region := s.Config.AwsRegion
	if region == "" {
		region = "us-east-1"
	}

	loadOpts = append(loadOpts, config.WithRegion(region))

	if c := defaultCreds(); c != nil {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(c))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*s3.Options)
	if s.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(s.Config.AwsEndpoint)
		})
	}

	return s3.NewFromConfig(cfg, clientOpts...), nil
}

func (s *S3Source) newSQSClient(ctx context.Context) (*sqs.Client, error) {
	var loadOpts []func(*config.LoadOptions) error
	if s.Config.AwsProfile != nil && *s.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*s.Config.AwsProfile))
	}

	region := s.Config.AwsRegion
	if region == "" {
		region = "us-east-1"
	}

	loadOpts = append(loadOpts, config.WithRegion(region))

	if c := defaultCreds(); c != nil {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(c))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*sqs.Options)
	if s.Config.AwsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *sqs.Options) { o.BaseEndpoint = aws.String(s.Config.AwsEndpoint) })
	}

	return sqs.NewFromConfig(cfg, clientOpts...), nil
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

			if err := s.readFile(s3Object.Bucket, s3Object.Key); err != nil {
				logger.Errorf("Error while reading file: %s", err)
			}
		}
	}
}

func (s *S3Source) getBucketContent() ([]s3types.Object, error) {
	logger := s.logger.WithField("method", "getBucketContent")
	logger.Debugf("Getting bucket content")

	bucketObjects := make([]s3types.Object, 0)

	var continuationToken *string

	for {
		out, err := s.s3Client.ListObjectsV2(s.ctx, &s3.ListObjectsV2Input{
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
				if !bucketObjects[i].LastModified.After(lastObjectDate) {
					break
				}

				newObject = true

				logger.Debugf("Found new object %s", *bucketObjects[i].Key)

				obj := S3Object{
					Bucket: s.Config.BucketName,
					Key:    *bucketObjects[i].Key,
				}

				select {
				case s.readerChan <- obj:
				case <-s.t.Dying():
					logger.Debug("tomb is dying, dropping object send")
					return nil
				}
			}

			if newObject {
				lastObjectDate = *bucketObjects[len(bucketObjects)-1].LastModified
			}
		}
	}
}

func extractBucketAndPrefixFromEventBridge(message *string) (string, string, error) {
	eventBody := S3Event{}

	if err := json.Unmarshal([]byte(*message), &eventBody); err != nil {
		return "", "", err
	}

	if eventBody.Detail.Bucket.Name != "" {
		return eventBody.Detail.Bucket.Name, eventBody.Detail.Object.Key, nil
	}

	return "", "", errors.New("invalid event body for event bridge format")
}

func extractBucketAndPrefixFromS3Notif(message *string) (string, string, error) {
	s3notifBody := events.S3Event{}

	if err := json.Unmarshal([]byte(*message), &s3notifBody); err != nil {
		return "", "", err
	}

	if len(s3notifBody.Records) == 0 {
		return "", "", errors.New("no records found in S3 notification")
	}

	if !strings.HasPrefix(s3notifBody.Records[0].EventName, "ObjectCreated:") {
		return "", "", fmt.Errorf("event %s is not supported", s3notifBody.Records[0].EventName)
	}

	return s3notifBody.Records[0].S3.Bucket.Name, s3notifBody.Records[0].S3.Object.Key, nil
}

func extractBucketAndPrefixFromSNSNotif(message *string) (string, string, error) {
	snsBody := SNSEvent{}

	if err := json.Unmarshal([]byte(*message), &snsBody); err != nil {
		return "", "", err
	}

	// It's just a SQS message wrapped in SNS
	return extractBucketAndPrefixFromS3Notif(&snsBody.Message)
}

func (s *S3Source) extractBucketAndPrefix(message *string) (string, string, error) {
	switch s.Config.SQSFormat {
	case SQSFormatEventBridge:
		bucket, key, err := extractBucketAndPrefixFromEventBridge(message)
		if err != nil {
			return "", "", err
		}
		return bucket, key, nil
	case SQSFormatS3Notification:
		bucket, key, err := extractBucketAndPrefixFromS3Notif(message)
		if err != nil {
			return "", "", err
		}
		return bucket, key, nil
	case SQSFormatSNS:
		bucket, key, err := extractBucketAndPrefixFromSNSNotif(message)
		if err != nil {
			return "", "", err
		}
		return bucket, key, nil
	default:
		bucket, key, err := extractBucketAndPrefixFromEventBridge(message)
		if err == nil {
			s.Config.SQSFormat = SQSFormatEventBridge
			return bucket, key, nil
		}

		bucket, key, err = extractBucketAndPrefixFromS3Notif(message)
		if err == nil {
			s.Config.SQSFormat = SQSFormatS3Notification
			return bucket, key, nil
		}

		bucket, key, err = extractBucketAndPrefixFromSNSNotif(message)
		if err == nil {
			s.Config.SQSFormat = SQSFormatSNS
			return bucket, key, nil
		}

		return "", "", errors.New("SQS message format not supported")
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
			logger.Trace("Polling SQS queue")

			out, err := s.sqsClient.ReceiveMessage(s.ctx, &sqs.ReceiveMessageInput{
				QueueUrl:            aws.String(s.Config.SQSName),
				MaxNumberOfMessages: 10,
				WaitTimeSeconds:     20, // Probably no need to make it configurable ?
			})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				logger.Errorf("Error while polling SQS: %s", err)
				continue
			}

			logger.Tracef("SQS output: %v", out)
			logger.Debugf("Received %d messages from SQS", len(out.Messages))

			for _, message := range out.Messages {
				if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
					metrics.S3DataSourceSQSMessagesReceived.WithLabelValues(s.Config.SQSName).Inc()
				}

				bucket, key, err := s.extractBucketAndPrefix(message.Body)
				if err != nil {
					logger.Errorf("Error while parsing SQS message: %s", err)
					// Always delete the message to avoid infinite loop
					_, err = s.sqsClient.DeleteMessage(s.ctx,
						&sqs.DeleteMessageInput{
							QueueUrl:      aws.String(s.Config.SQSName),
							ReceiptHandle: message.ReceiptHandle,
						})
					if err != nil {
						logger.Errorf("Error while deleting SQS message: %s", err)
					}

					continue
				}

				logger.Debugf("Received SQS message for object %s/%s", bucket, key)

				// don't block if readManager has quit
				select {
				case s.readerChan <- S3Object{Key: key, Bucket: bucket}:
				case <-s.t.Dying():
					logger.Debug("tomb is dying, dropping object send")
					return nil
				}

				_, err = s.sqsClient.DeleteMessage(s.ctx,
					&sqs.DeleteMessageInput{
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
	// TODO: Handle SSE-C
	var scanner *bufio.Scanner

	logger := s.logger.WithFields(log.Fields{
		"method": "readFile",
		"bucket": bucket,
		"key":    key,
	})

	output, err := s.s3Client.GetObject(s.ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to get object %s/%s: %w", bucket, key, err)
	}
	defer output.Body.Close()

	if strings.HasSuffix(key, ".gz") {
		// This *might* be a gzipped file, but sometimes the SDK will decompress the data for us (it's not clear when it happens, only had the issue with cloudtrail logs)
		header := make([]byte, 2)

		_, err := output.Body.Read(header)
		if err != nil {
			return fmt.Errorf("failed to read header of object %s/%s: %w", bucket, key, err)
		}

		if header[0] == 0x1f && header[1] == 0x8b {
			gz, err := gzip.NewReader(io.MultiReader(bytes.NewReader(header), output.Body))
			if err != nil {
				return fmt.Errorf("failed to create gzip reader for object %s/%s: %w", bucket, key, err)
			}
			scanner = bufio.NewScanner(gz)
		} else {
			scanner = bufio.NewScanner(io.MultiReader(bytes.NewReader(header), output.Body))
		}
	} else {
		scanner = bufio.NewScanner(output.Body)
	}

	if s.Config.MaxBufferSize > 0 {
		s.logger.Infof("Setting max buffer size to %d", s.Config.MaxBufferSize)

		buf := make([]byte, 0, bufio.MaxScanTokenSize)
		scanner.Buffer(buf, s.Config.MaxBufferSize)
	}

	for scanner.Scan() {
		select {
		case <-s.t.Dying():
			s.logger.Infof("Shutting down reader for %s/%s", bucket, key)
			return nil
		default:
			text := scanner.Text()
			logger.Tracef("Read line %s", text)

			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.S3DataSourceLinesRead.With(prometheus.Labels{"bucket": bucket, "datasource_type": "s3", "acquis_type": s.Config.Labels["type"]}).Inc()
			}

			l := types.Line{}
			l.Raw = text
			l.Labels = s.Config.Labels
			l.Time = time.Now().UTC()
			l.Process = true
			l.Module = s.GetName()

			switch s.metricsLevel {
			case metrics.AcquisitionMetricsLevelFull:
				l.Src = bucket + "/" + key
			case metrics.AcquisitionMetricsLevelAggregated, metrics.AcquisitionMetricsLevelNone: // Even if metrics are disabled, we want to source in the event
				l.Src = bucket
			}

			evt := types.MakeEvent(s.Config.UseTimeMachine, types.LOG, true)
			evt.Line = l

			// don't block in shutdown
			select {
			case s.out <-evt:
			case <-s.t.Dying():
				s.logger.Infof("tomb is dying, dropping event for %s/%s", bucket, key)
				return nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read object %s/%s: %s", bucket, key, err)
	}

	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.S3DataSourceObjectsRead.WithLabelValues(bucket).Inc()
	}

	return nil
}

func (s *S3Source) GetUuid() string {
	return s.Config.UniqueId
}

func (*S3Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.S3DataSourceLinesRead, metrics.S3DataSourceObjectsRead, metrics.S3DataSourceSQSMessagesReceived}
}

func (*S3Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.S3DataSourceLinesRead, metrics.S3DataSourceObjectsRead, metrics.S3DataSourceSQSMessagesReceived}
}

func (s *S3Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = S3Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse S3Acquisition configuration: %s", yaml.FormatError(err, false, false))
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

	if s.Config.MaxBufferSize == 0 {
		s.Config.MaxBufferSize = bufio.MaxScanTokenSize
	}

	if s.Config.PollingMethod != PollMethodList && s.Config.PollingMethod != PollMethodSQS {
		return fmt.Errorf("invalid polling method %s", s.Config.PollingMethod)
	}

	if s.Config.BucketName != "" && s.Config.SQSName != "" {
		return errors.New("bucket_name and sqs_name are mutually exclusive")
	}

	if s.Config.PollingMethod == PollMethodSQS && s.Config.SQSName == "" {
		return errors.New("sqs_name is required when using sqs polling method")
	}

	if s.Config.BucketName == "" && s.Config.PollingMethod == PollMethodList {
		return errors.New("bucket_name is required")
	}

	if s.Config.SQSFormat != "" && s.Config.SQSFormat != SQSFormatEventBridge && s.Config.SQSFormat != SQSFormatS3Notification && s.Config.SQSFormat != SQSFormatSNS {
		return fmt.Errorf("invalid sqs_format %s, must be empty, %s, %s or %s", s.Config.SQSFormat, SQSFormatEventBridge, SQSFormatS3Notification, SQSFormatSNS)
	}

	return nil
}

func (s *S3Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	if s.Config.SQSName != "" {
		s.logger = logger.WithFields(log.Fields{
			"queue": s.Config.SQSName,
		})
	} else {
		s.logger = logger.WithFields(log.Fields{
			"bucket": s.Config.BucketName,
			"prefix": s.Config.Prefix,
		})
	}

	if !s.Config.UseTimeMachine {
		s.logger.Warning("use_time_machine is not set to true in the datasource configuration. This will likely lead to false positives as S3 logs are not processed in real time.")
	}

	if s.Config.PollingMethod == PollMethodList {
		s.logger.Warning("Polling method is set to list. This is not recommended as it will not scale well. Consider using SQS instead.")
	}

	client, err := s.newS3Client(ctx)
	if err != nil {
		return err
	}

	s.s3Client = client

	if s.Config.PollingMethod == PollMethodSQS {
		sqsClient, err := s.newSQSClient(ctx)
		if err != nil {
			return err
		}

		s.sqsClient = sqsClient
	}

	return nil
}

func (s *S3Source) ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "s3://") {
		return fmt.Errorf("invalid DSN %s for S3 source, must start with s3://", dsn)
	}

	s.Config = S3Configuration{}
	s.logger = logger.WithFields(log.Fields{
		"bucket": s.Config.BucketName,
		"prefix": s.Config.Prefix,
	})

	dsn = strings.TrimPrefix(dsn, "s3://")
	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty s3:// DSN")
	}

	if len(args) == 2 && args[1] != "" {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse s3 args: %w", err)
		}

		for key, value := range params {
			switch key {
			case "log_level":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'log_level'")
				}

				lvl, err := log.ParseLevel(value[0])
				if err != nil {
					return fmt.Errorf("unknown level %s: %w", value[0], err)
				}

				s.logger.Logger.SetLevel(lvl)
			case "max_buffer_size":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'max_buffer_size'")
				}

				maxBufferSize, err := strconv.Atoi(value[0])
				if err != nil {
					return fmt.Errorf("invalid value for 'max_buffer_size': %w", err)
				}

				s.logger.Debugf("Setting max buffer size to %d", maxBufferSize)
				s.Config.MaxBufferSize = maxBufferSize
			default:
				return fmt.Errorf("unknown parameter %s", key)
			}
		}
	}

	s.Config.Labels = labels
	s.Config.Mode = configuration.CAT_MODE
	s.Config.UniqueId = uuid

	pathParts := strings.Split(args[0], "/")
	s.logger.Debugf("pathParts: %v", pathParts)

	// FIXME: handle s3://bucket/
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

	client, err := s.newS3Client(ctx)
	if err != nil {
		return err
	}

	s.s3Client = client

	return nil
}

func (s *S3Source) GetMode() string {
	return s.Config.Mode
}

func (*S3Source) GetName() string {
	return "s3"
}

func (s *S3Source) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	s.logger.Infof("starting acquisition of %s/%s/%s", s.Config.BucketName, s.Config.Prefix, s.Config.Key)
	s.out = out
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.Config.UseTimeMachine = true
	s.t = t

	if s.Config.Key != "" {
		err := s.readFile(s.Config.BucketName, s.Config.Key)
		if err != nil {
			return err
		}
	} else {
		// No key, get everything in the bucket based on the prefix
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

	t.Kill(nil)

	return nil
}

func (s *S3Source) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	s.t = t
	s.out = out
	s.readerChan = make(chan S3Object, 100) // FIXME: does this needs to be buffered?
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.logger.Infof("starting acquisition of %s/%s", s.Config.BucketName, s.Config.Prefix)
	t.Go(func() error {
		s.readManager()
		return nil
	})

	if s.Config.PollingMethod == PollMethodSQS {
		t.Go(func() error {
			return s.sqsPoll()
		})
	} else {
		t.Go(func() error {
			return s.listPoll()
		})
	}

	return nil
}

func (*S3Source) CanRun() error {
	return nil
}

func (s *S3Source) Dump() any {
	return s
}
