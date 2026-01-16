package cloudwatchacquisition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

var streamIndexMutex = sync.Mutex{}

// LogStreamTailConfig is the configuration for one given stream within one group
type LogStreamTailConfig struct {
	GroupName                  string
	StreamName                 string
	GetLogEventsPagesLimit     int32
	PollStreamInterval         time.Duration
	StreamReadTimeout          time.Duration
	PrependCloudwatchTimestamp *bool
	Labels                     map[string]string
	logger                     *logrus.Entry
	ExpectMode                 int
	t                          tomb.Tomb
	StartTime, EndTime         time.Time // only used for CatMode
}

var (
	def_DescribeLogStreamsLimit = int32(50)
	def_PollNewStreamInterval   = 10 * time.Second
	def_MaxStreamAge            = 5 * time.Minute
	def_PollStreamInterval      = 10 * time.Second
	def_AwsApiCallTimeout       = 10 * time.Second
	def_StreamReadTimeout       = 10 * time.Minute
	def_PollDeadStreamInterval  = 10 * time.Second
	def_GetLogEventsPagesLimit  = int32(1000)
	def_AwsConfigDir            = ""
)

func (s *Source) newClient(ctx context.Context) error {
	var loadOpts []func(*config.LoadOptions) error
	if s.Config.AwsProfile != nil && *s.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*s.Config.AwsProfile))
	}

	region := s.Config.AwsRegion
	if region == "" {
		region = "us-east-1"
	}

	loadOpts = append(loadOpts, config.WithRegion(region))

	var sharedConfigProfileNotExistError config.SharedConfigProfileNotExistError

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if errors.As(err, &sharedConfigProfileNotExistError) {
		// Fallback for tests/CI where the profile is not present
		s.logger.Debugf("shared config profile %q not found; retrying without profile", aws.ToString(s.Config.AwsProfile))
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithCredentialsProvider(aws.AnonymousCredentials{}),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to load aws config: %w", err)
	}

	var clientOpts []func(*cloudwatchlogs.Options)

	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		s.logger.Debugf("[testing] overloading endpoint with %s", v)

		clientOpts = append(clientOpts, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(v)
		})
	}

	s.cwClient = cloudwatchlogs.NewFromConfig(cfg, clientOpts...)

	return nil
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.t = t
	monitChan := make(chan LogStreamTailConfig)

	t.Go(func() error {
		return s.LogStreamManager(ctx, monitChan, out)
	})

	return s.WatchLogGroupForStreams(ctx, monitChan)
}

func (s *Source) WatchLogGroupForStreams(ctx context.Context, out chan LogStreamTailConfig) error {
	s.logger.Debugf("Starting to watch group (interval:%s)", s.Config.PollNewStreamInterval)
	ticker := time.NewTicker(*s.Config.PollNewStreamInterval)

	for {
		select {
		case <-s.t.Dying():
			s.logger.Infof("stopping group watch")
			return nil
		case <-ticker.C:
			p := cloudwatchlogs.NewDescribeLogStreamsPaginator(
				s.cwClient,
				&cloudwatchlogs.DescribeLogStreamsInput{
					LogGroupName: aws.String(s.Config.GroupName),
					Descending:   aws.Bool(true),
					OrderBy:      cwTypes.OrderByLastEventTime,
					Limit:        s.Config.DescribeLogStreamsLimit,
				},
				)

			Pageloop:
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("while describing group %s: %w", s.Config.GroupName, err)
				}

				for _, event := range page.LogStreams {
					// we check if the stream has been written to recently enough to be monitored
					if event.LastIngestionTime == nil {
						continue
					}

					// aws uses millisecond since the epoch
					oldest := time.Now().UTC().Add(-*s.Config.MaxStreamAge)
					// TBD : verify that this is correct : Unix 2nd arg expects Nanoseconds, and have a code that is more explicit.
					LastIngestionTime := time.Unix(0, *event.LastIngestionTime*int64(time.Millisecond))
					if LastIngestionTime.Before(oldest) {
						s.logger.Tracef("stop iteration, %s reached oldest age, stop (%s < %s)", aws.ToString(event.LogStreamName), LastIngestionTime, time.Now().UTC().Add(-*s.Config.MaxStreamAge))
						break Pageloop
					}

					var expectMode int
					if !s.Config.UseTimeMachine {
						expectMode = pipeline.LIVE
					} else {
						expectMode = pipeline.TIMEMACHINE
					}

					monitorStream := LogStreamTailConfig{
						GroupName:                  s.Config.GroupName,
						StreamName:                 aws.ToString(event.LogStreamName),
						GetLogEventsPagesLimit:     *s.Config.GetLogEventsPagesLimit,
						PollStreamInterval:         *s.Config.PollStreamInterval,
						StreamReadTimeout:          *s.Config.StreamReadTimeout,
						PrependCloudwatchTimestamp: s.Config.PrependCloudwatchTimestamp,
						ExpectMode:                 expectMode,
						Labels:                     s.Config.Labels,
					}
					out <- monitorStream
				}
			}
		}
	}
}

// LogStreamManager receives the potential streams to monitor, and starts a go routine when needed
func (s *Source) LogStreamManager(ctx context.Context, in chan LogStreamTailConfig, outChan chan pipeline.Event) error {
	s.logger.Debugf("starting to monitor streams for %s", s.Config.GroupName)

	pollDeadStreamInterval := time.NewTicker(def_PollDeadStreamInterval)

	for {
		select {
		case newStream := <-in: //nolint:govet // copylocks won't matter if the tomb is not initialized
			shouldCreate := true

			s.logger.Tracef("received new streams to monitor : %s/%s", newStream.GroupName, newStream.StreamName)

			if s.Config.StreamName != nil && newStream.StreamName != *s.Config.StreamName {
				s.logger.Tracef("stream %s != %s", newStream.StreamName, *s.Config.StreamName)
				continue
			}

			if s.Config.StreamRegexp != nil {
				match, err := regexp.MatchString(*s.Config.StreamRegexp, newStream.StreamName)
				if err != nil {
					s.logger.Warningf("invalid regexp : %s", err)
				} else if !match {
					s.logger.Tracef("stream %s doesn't match %s", newStream.StreamName, *s.Config.StreamRegexp)
					continue
				}
			}

			for idx, stream := range s.monitoredStreams {
				if newStream.GroupName == stream.GroupName && newStream.StreamName == stream.StreamName {
					// stream exists, but is dead, remove it from list
					if !stream.t.Alive() {
						s.logger.Debugf("stream %s already exists, but is dead", newStream.StreamName)
						s.monitoredStreams = slices.Delete(s.monitoredStreams, idx, idx+1)

						if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
							metrics.CloudWatchDatasourceOpenedStreams.With(prometheus.Labels{"group": newStream.GroupName}).Dec()
						}

						break
					}

					shouldCreate = false

					break
				}
			}

			// let's start watching this stream
			if shouldCreate {
				if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
					metrics.CloudWatchDatasourceOpenedStreams.With(prometheus.Labels{"group": newStream.GroupName}).Inc()
				}

				newStream.t = tomb.Tomb{}
				newStream.logger = s.logger.WithField("stream", newStream.StreamName)
				s.logger.Debugf("starting tail of stream %s", newStream.StreamName)
				newStream.t.Go(func() error {
					return s.TailLogStream(ctx, &newStream, outChan)
				})

				s.monitoredStreams = append(s.monitoredStreams, &newStream)
			}
		case <-pollDeadStreamInterval.C:
			newMonitoredStreams := s.monitoredStreams[:0]

			for idx, stream := range s.monitoredStreams {
				if !s.monitoredStreams[idx].t.Alive() {
					s.logger.Debugf("remove dead stream %s", stream.StreamName)

					if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.CloudWatchDatasourceOpenedStreams.With(prometheus.Labels{"group": s.monitoredStreams[idx].GroupName}).Dec()
					}
				} else {
					newMonitoredStreams = append(newMonitoredStreams, stream)
				}
			}

			s.monitoredStreams = newMonitoredStreams
		case <-s.t.Dying():
			s.logger.Infof("LogStreamManager for %s is dying, %d alive streams", s.Config.GroupName, len(s.monitoredStreams))

			for idx, stream := range s.monitoredStreams {
				if s.monitoredStreams[idx].t.Alive() {
					s.logger.Debugf("killing stream %s", stream.StreamName)
					s.monitoredStreams[idx].t.Kill(nil)

					if err := s.monitoredStreams[idx].t.Wait(); err != nil {
						s.logger.Debugf("error while waiting for death of %s : %s", stream.StreamName, err)
					}
				}
			}

			s.monitoredStreams = nil
			s.logger.Debugf("routine cleanup done, return")

			return nil
		}
	}
}

func (s *Source) TailLogStream(ctx context.Context, cfg *LogStreamTailConfig, outChan chan pipeline.Event) error {
	var startFrom *string

	lastReadMessage := time.Now().UTC()
	ticker := time.NewTicker(cfg.PollStreamInterval)

	// resume at existing index if we already had
	streamIndexMutex.Lock()

	if v := s.streamIndexes[cfg.GroupName+"+"+cfg.StreamName]; v != "" {
		cfg.logger.Debugf("restarting on index %s", v)
		startFrom = &v
	}

	streamIndexMutex.Unlock()

	for {
		select {
		case <-ticker.C:
			p := cloudwatchlogs.NewGetLogEventsPaginator(
				s.cwClient,
				&cloudwatchlogs.GetLogEventsInput{
					Limit:         aws.Int32(cfg.GetLogEventsPagesLimit),
					LogGroupName:  aws.String(cfg.GroupName),
					LogStreamName: aws.String(cfg.StreamName),
					NextToken:     startFrom,   // if set, StartFromHead is ignored by AWS
					StartFromHead: aws.Bool(true),
				},
				)
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					newerr := fmt.Errorf("while reading %s/%s: %w", cfg.GroupName, cfg.StreamName, err)
					cfg.logger.Warningf("err: %s", newerr)

					return newerr
				}

				// Update token/index
				startFrom = page.NextForwardToken
				if startFrom != nil {
					streamIndexMutex.Lock()
					s.streamIndexes[cfg.GroupName+"+"+cfg.StreamName] = *startFrom
					streamIndexMutex.Unlock()
				}

				if len(page.Events) > 0 {
					lastReadMessage = time.Now().UTC()
				}

				for _, ev := range page.Events {
					evt, err := cwLogToEvent(ev, cfg)
					if err != nil {
						cfg.logger.Warningf("cwLogToEvent error, discarded event : %s", err)
						continue
					}

					if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.CloudWatchDatasourceLinesRead.With(prometheus.Labels{
							"group": cfg.GroupName, "stream": cfg.StreamName,
							"datasource_type": ModuleName, "acquis_type": evt.Line.Labels["type"],
						}).Inc()
					}

					outChan <- evt
				}

				if time.Since(lastReadMessage) > cfg.StreamReadTimeout {
					cfg.logger.Infof("%s/%s reached timeout (%s) (last message was %s)",
						cfg.GroupName, cfg.StreamName, time.Since(lastReadMessage), lastReadMessage)

					return nil
				}
			}

		case <-cfg.t.Dying():
			cfg.logger.Infof("logstream tail stopping")
			return errors.New("killed")
		}
	}
}

func (s *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, _ *tomb.Tomb) error {
	// StreamName string, Start time.Time, End time.Time
	cfg := LogStreamTailConfig{
		GroupName:              s.Config.GroupName,
		StreamName:             *s.Config.StreamName,
		StartTime:              *s.Config.StartTime,
		EndTime:                *s.Config.EndTime,
		GetLogEventsPagesLimit: *s.Config.GetLogEventsPagesLimit,
		logger: s.logger.WithFields(logrus.Fields{
			"group":  s.Config.GroupName,
			"stream": *s.Config.StreamName,
		}),
		Labels:     s.Config.Labels,
		ExpectMode: pipeline.TIMEMACHINE,
	}

	return s.CatLogStream(ctx, &cfg, out)
}

func (s *Source) CatLogStream(ctx context.Context, cfg *LogStreamTailConfig, outChan chan pipeline.Event) error {
	var startFrom *string

	head := true
	// convert the times
	startTime := cfg.StartTime.UTC().Unix() * 1000
	endTime := cfg.EndTime.UTC().Unix() * 1000

	hasMoreEvents := true
	for hasMoreEvents {
		select {
		default:
			cfg.logger.Tracef("Calling GetLogEventsPagesWithContext(%s, %s), startTime:%d / endTime:%d",
				cfg.GroupName, cfg.StreamName, startTime, endTime)
			cfg.logger.Tracef("startTime:%s / endTime:%s", cfg.StartTime, cfg.EndTime)

			if startFrom != nil {
				cfg.logger.Tracef("next_token: %s", *startFrom)
			}

			p := cloudwatchlogs.NewGetLogEventsPaginator(
				s.cwClient,
				&cloudwatchlogs.GetLogEventsInput{
					Limit:         aws.Int32(10),
					LogGroupName:  aws.String(cfg.GroupName),
					LogStreamName: aws.String(cfg.StreamName),
					StartTime:     aws.Int64(startTime),
					EndTime:       aws.Int64(endTime),
					StartFromHead: &head,
					NextToken:     startFrom,
				},
				)
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("while reading logs from %s/%s: %w", cfg.GroupName, cfg.StreamName, err)
				}

				for _, e := range page.Events {
					evt, err := cwLogToEvent(e, cfg)
					if err != nil {
						cfg.logger.Warningf("discard event: %s", err)
					}

					cfg.logger.Debugf("pushing message: %s", evt.Line.Raw)

					outChan <- evt
				}

				if startFrom != nil && page.NextForwardToken != nil && *page.NextForwardToken == *startFrom {
					cfg.logger.Debugf("reached end of available events")
					hasMoreEvents = false
					break
				}

				startFrom = page.NextForwardToken
			}

			cfg.logger.Tracef("after GetLogEventsPagesWithContext")
		case <-s.t.Dying():
			cfg.logger.Warningf("cat stream killed")
			return nil
		}
	}

	cfg.logger.Tracef("CatLogStream out")

	return nil
}

func cwLogToEvent(log cwTypes.OutputLogEvent, cfg *LogStreamTailConfig) (pipeline.Event, error) {
	evt := pipeline.MakeEvent(cfg.ExpectMode == pipeline.TIMEMACHINE, pipeline.LOG, true)

	if log.Message == nil {
		return evt, errors.New("nil message")
	}

	msg := *log.Message
	if cfg.PrependCloudwatchTimestamp != nil && *cfg.PrependCloudwatchTimestamp {
		eventTimestamp := time.Unix(0, *log.Timestamp*int64(time.Millisecond))
		msg = eventTimestamp.String() + " " + msg
	}

	l := pipeline.Line{
		Raw: msg,
		Labels: cfg.Labels,
		Time: time.Now().UTC(),
		Src: cfg.GroupName + "/" + cfg.StreamName,
		Process: true,
		Module: ModuleName,
	}

	evt.Line = l
	cfg.logger.Debugf("returned event labels : %+v", evt.Line.Labels)

	return evt, nil
}
