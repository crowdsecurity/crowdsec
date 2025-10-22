package cloudwatchacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var streamIndexMutex = sync.Mutex{}

// CloudwatchSource is the runtime instance keeping track of N streams within 1 cloudwatch group
type CloudwatchSource struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       CloudwatchSourceConfiguration
	// runtime stuff
	logger           *log.Entry
	t                *tomb.Tomb
	cwClient         *cloudwatchlogs.Client
	monitoredStreams []*LogStreamTailConfig
	streamIndexes    map[string]string
}

// CloudwatchSourceConfiguration allows user to define one or more streams to monitor within a cloudwatch log group
type CloudwatchSourceConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	GroupName                         string         `yaml:"group_name"`              // the group name to be monitored
	StreamRegexp                      *string        `yaml:"stream_regexp,omitempty"` // allow to filter specific streams
	StreamName                        *string        `yaml:"stream_name,omitempty"`
	StartTime, EndTime                *time.Time     `yaml:"-"`
	DescribeLogStreamsLimit           *int32         `yaml:"describelogstreams_limit,omitempty"` // batch size for DescribeLogStreamsPagesWithContext
	GetLogEventsPagesLimit            *int32         `yaml:"getlogeventspages_limit,omitempty"`
	PollNewStreamInterval             *time.Duration `yaml:"poll_new_stream_interval,omitempty"` // frequency at which we poll for new streams within the log group
	MaxStreamAge                      *time.Duration `yaml:"max_stream_age,omitempty"`           // monitor only streams that have been updated within $duration
	PollStreamInterval                *time.Duration `yaml:"poll_stream_interval,omitempty"`     // frequency at which we poll each stream
	StreamReadTimeout                 *time.Duration `yaml:"stream_read_timeout,omitempty"`      // stop monitoring streams that haven't been updated within $duration, might be reopened later tho
	AwsApiCallTimeout                 *time.Duration `yaml:"aws_api_timeout,omitempty"`
	AwsProfile                        *string        `yaml:"aws_profile,omitempty"`
	PrependCloudwatchTimestamp        *bool          `yaml:"prepend_cloudwatch_timestamp,omitempty"`
	AwsConfigDir                      *string        `yaml:"aws_config_dir,omitempty"`
	AwsRegion                         string        `yaml:"aws_region,omitempty"`
}

// LogStreamTailConfig is the configuration for one given stream within one group
type LogStreamTailConfig struct {
	GroupName                  string
	StreamName                 string
	GetLogEventsPagesLimit     int32
	PollStreamInterval         time.Duration
	StreamReadTimeout          time.Duration
	PrependCloudwatchTimestamp *bool
	Labels                     map[string]string
	logger                     *log.Entry
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

func (cw *CloudwatchSource) GetUuid() string {
	return cw.Config.UniqueId
}

func (cw *CloudwatchSource) UnmarshalConfig(yamlConfig []byte) error {
	cw.Config = CloudwatchSourceConfiguration{}
	if err := yaml.UnmarshalWithOptions(yamlConfig, &cw.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("cannot parse CloudwatchSource configuration: %s", yaml.FormatError(err, false, false))
	}

	if cw.Config.GroupName == "" {
		return errors.New("group_name is mandatory for CloudwatchSource")
	}

	if cw.Config.Mode == "" {
		cw.Config.Mode = configuration.TAIL_MODE
	}

	if cw.Config.DescribeLogStreamsLimit == nil {
		cw.Config.DescribeLogStreamsLimit = &def_DescribeLogStreamsLimit
	}

	if cw.Config.PollNewStreamInterval == nil {
		cw.Config.PollNewStreamInterval = &def_PollNewStreamInterval
	}

	if cw.Config.MaxStreamAge == nil {
		cw.Config.MaxStreamAge = &def_MaxStreamAge
	}

	if cw.Config.PollStreamInterval == nil {
		cw.Config.PollStreamInterval = &def_PollStreamInterval
	}

	if cw.Config.StreamReadTimeout == nil {
		cw.Config.StreamReadTimeout = &def_StreamReadTimeout
	}

	if cw.Config.GetLogEventsPagesLimit == nil {
		cw.Config.GetLogEventsPagesLimit = &def_GetLogEventsPagesLimit
	}

	if cw.Config.AwsApiCallTimeout == nil {
		cw.Config.AwsApiCallTimeout = &def_AwsApiCallTimeout
	}

	if cw.Config.AwsConfigDir == nil {
		cw.Config.AwsConfigDir = &def_AwsConfigDir
	}

	return nil
}

func (cw *CloudwatchSource) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	err := cw.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	cw.metricsLevel = metricsLevel

	cw.logger = logger.WithField("group", cw.Config.GroupName)

	cw.logger.Debugf("Starting configuration for Cloudwatch group %s", cw.Config.GroupName)
	cw.logger.Tracef("describelogstreams_limit set to %d", *cw.Config.DescribeLogStreamsLimit)
	cw.logger.Tracef("poll_new_stream_interval set to %v", *cw.Config.PollNewStreamInterval)
	cw.logger.Tracef("max_stream_age set to %v", *cw.Config.MaxStreamAge)
	cw.logger.Tracef("poll_stream_interval set to %v", *cw.Config.PollStreamInterval)
	cw.logger.Tracef("stream_read_timeout set to %v", *cw.Config.StreamReadTimeout)
	cw.logger.Tracef("getlogeventspages_limit set to %v", *cw.Config.GetLogEventsPagesLimit)
	cw.logger.Tracef("aws_api_timeout set to %v", *cw.Config.AwsApiCallTimeout)

	if *cw.Config.MaxStreamAge > *cw.Config.StreamReadTimeout {
		cw.logger.Warningf("max_stream_age > stream_read_timeout, stream might keep being opened/closed")
	}

	cw.logger.Tracef("aws_config_dir set to %s", *cw.Config.AwsConfigDir)

	if *cw.Config.AwsConfigDir != "" {
		_, err := os.Stat(*cw.Config.AwsConfigDir)
		if err != nil {
			cw.logger.Errorf("can't read aws_config_dir '%s' got err %s", *cw.Config.AwsConfigDir, err)
			return fmt.Errorf("can't read aws_config_dir %s got err %w ", *cw.Config.AwsConfigDir, err)
		}

		os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
		// as aws sdk relies on $HOME, let's allow the user to override it :)
		os.Setenv("AWS_CONFIG_FILE", fmt.Sprintf("%s/config", *cw.Config.AwsConfigDir))
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", fmt.Sprintf("%s/credentials", *cw.Config.AwsConfigDir))
	} else {
		if cw.Config.AwsRegion == "" {
			cw.logger.Errorf("aws_region is not specified, specify it or aws_config_dir")
			return errors.New("aws_region is not specified, specify it or aws_config_dir")
		}

		os.Setenv("AWS_REGION", cw.Config.AwsRegion)
	}

	if err := cw.newClient(ctx); err != nil {
		return err
	}

	cw.streamIndexes = make(map[string]string)

	targetStream := "*"

	if cw.Config.StreamRegexp != nil {
		if _, err := regexp.Compile(*cw.Config.StreamRegexp); err != nil {
			return fmt.Errorf("while compiling regexp '%s': %w", *cw.Config.StreamRegexp, err)
		}

		targetStream = *cw.Config.StreamRegexp
	} else if cw.Config.StreamName != nil {
		targetStream = *cw.Config.StreamName
	}

	cw.logger.Infof("Adding cloudwatch group '%s' (stream:%s) to datasources", cw.Config.GroupName, targetStream)

	return nil
}

func (cw *CloudwatchSource) newClient(ctx context.Context) error {
	var loadOpts []func(*config.LoadOptions) error
	if cw.Config.AwsProfile != nil && *cw.Config.AwsProfile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(*cw.Config.AwsProfile))
	}

	region := cw.Config.AwsRegion
	if region == "" {
		region = "us-east-1"
	}

	loadOpts = append(loadOpts, config.WithRegion(region))

	var sharedConfigProfileNotExistError config.SharedConfigProfileNotExistError

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if errors.As(err, &sharedConfigProfileNotExistError) {
		// Fallback for tests/CI where the profile is not present
		cw.logger.Debugf("shared config profile %q not found; retrying without profile", aws.ToString(cw.Config.AwsProfile))
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
		cw.logger.Debugf("[testing] overloading endpoint with %s", v)

		clientOpts = append(clientOpts, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(v)
		})
	}

	cw.cwClient = cloudwatchlogs.NewFromConfig(cfg, clientOpts...)

	return nil
}

func (cw *CloudwatchSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	cw.t = t
	monitChan := make(chan LogStreamTailConfig)

	t.Go(func() error {
		return cw.LogStreamManager(ctx, monitChan, out)
	})

	return cw.WatchLogGroupForStreams(ctx, monitChan)
}

func (*CloudwatchSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.CloudWatchDatasourceLinesRead, metrics.CloudWatchDatasourceOpenedStreams}
}

func (*CloudwatchSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.CloudWatchDatasourceLinesRead, metrics.CloudWatchDatasourceOpenedStreams}
}

func (cw *CloudwatchSource) GetMode() string {
	return cw.Config.Mode
}

func (*CloudwatchSource) GetName() string {
	return "cloudwatch"
}

func (*CloudwatchSource) CanRun() error {
	return nil
}

func (cw *CloudwatchSource) Dump() any {
	return cw
}

func (cw *CloudwatchSource) WatchLogGroupForStreams(ctx context.Context, out chan LogStreamTailConfig) error {
	cw.logger.Debugf("Starting to watch group (interval:%s)", cw.Config.PollNewStreamInterval)
	ticker := time.NewTicker(*cw.Config.PollNewStreamInterval)

	for {
		select {
		case <-cw.t.Dying():
			cw.logger.Infof("stopping group watch")
			return nil
		case <-ticker.C:
			p := cloudwatchlogs.NewDescribeLogStreamsPaginator(
				cw.cwClient,
				&cloudwatchlogs.DescribeLogStreamsInput{
					LogGroupName: aws.String(cw.Config.GroupName),
					Descending:   aws.Bool(true),
					OrderBy:      cwTypes.OrderByLastEventTime,
					Limit:        cw.Config.DescribeLogStreamsLimit,
				},
				)

			Pageloop:
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("while describing group %s: %w", cw.Config.GroupName, err)
				}

				for _, event := range page.LogStreams {
					// we check if the stream has been written to recently enough to be monitored
					if event.LastIngestionTime == nil {
						continue
					}

					// aws uses millisecond since the epoch
					oldest := time.Now().UTC().Add(-*cw.Config.MaxStreamAge)
					// TBD : verify that this is correct : Unix 2nd arg expects Nanoseconds, and have a code that is more explicit.
					LastIngestionTime := time.Unix(0, *event.LastIngestionTime*int64(time.Millisecond))
					if LastIngestionTime.Before(oldest) {
						cw.logger.Tracef("stop iteration, %s reached oldest age, stop (%s < %s)", aws.ToString(event.LogStreamName), LastIngestionTime, time.Now().UTC().Add(-*cw.Config.MaxStreamAge))
						break Pageloop
					}

					var expectMode int
					if !cw.Config.UseTimeMachine {
						expectMode = types.LIVE
					} else {
						expectMode = types.TIMEMACHINE
					}

					monitorStream := LogStreamTailConfig{
						GroupName:                  cw.Config.GroupName,
						StreamName:                 aws.ToString(event.LogStreamName),
						GetLogEventsPagesLimit:     *cw.Config.GetLogEventsPagesLimit,
						PollStreamInterval:         *cw.Config.PollStreamInterval,
						StreamReadTimeout:          *cw.Config.StreamReadTimeout,
						PrependCloudwatchTimestamp: cw.Config.PrependCloudwatchTimestamp,
						ExpectMode:                 expectMode,
						Labels:                     cw.Config.Labels,
					}
					out <- monitorStream
				}
			}
		}
	}
}

// LogStreamManager receives the potential streams to monitor, and starts a go routine when needed
func (cw *CloudwatchSource) LogStreamManager(ctx context.Context, in chan LogStreamTailConfig, outChan chan types.Event) error {
	cw.logger.Debugf("starting to monitor streams for %s", cw.Config.GroupName)

	pollDeadStreamInterval := time.NewTicker(def_PollDeadStreamInterval)

	for {
		select {
		case newStream := <-in: //nolint:govet // copylocks won't matter if the tomb is not initialized
			shouldCreate := true

			cw.logger.Tracef("received new streams to monitor : %s/%s", newStream.GroupName, newStream.StreamName)

			if cw.Config.StreamName != nil && newStream.StreamName != *cw.Config.StreamName {
				cw.logger.Tracef("stream %s != %s", newStream.StreamName, *cw.Config.StreamName)
				continue
			}

			if cw.Config.StreamRegexp != nil {
				match, err := regexp.MatchString(*cw.Config.StreamRegexp, newStream.StreamName)
				if err != nil {
					cw.logger.Warningf("invalid regexp : %s", err)
				} else if !match {
					cw.logger.Tracef("stream %s doesn't match %s", newStream.StreamName, *cw.Config.StreamRegexp)
					continue
				}
			}

			for idx, stream := range cw.monitoredStreams {
				if newStream.GroupName == stream.GroupName && newStream.StreamName == stream.StreamName {
					// stream exists, but is dead, remove it from list
					if !stream.t.Alive() {
						cw.logger.Debugf("stream %s already exists, but is dead", newStream.StreamName)
						cw.monitoredStreams = slices.Delete(cw.monitoredStreams, idx, idx+1)

						if cw.metricsLevel != metrics.AcquisitionMetricsLevelNone {
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
				if cw.metricsLevel != metrics.AcquisitionMetricsLevelNone {
					metrics.CloudWatchDatasourceOpenedStreams.With(prometheus.Labels{"group": newStream.GroupName}).Inc()
				}

				newStream.t = tomb.Tomb{}
				newStream.logger = cw.logger.WithField("stream", newStream.StreamName)
				cw.logger.Debugf("starting tail of stream %s", newStream.StreamName)
				newStream.t.Go(func() error {
					return cw.TailLogStream(ctx, &newStream, outChan)
				})

				cw.monitoredStreams = append(cw.monitoredStreams, &newStream)
			}
		case <-pollDeadStreamInterval.C:
			newMonitoredStreams := cw.monitoredStreams[:0]

			for idx, stream := range cw.monitoredStreams {
				if !cw.monitoredStreams[idx].t.Alive() {
					cw.logger.Debugf("remove dead stream %s", stream.StreamName)

					if cw.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.CloudWatchDatasourceOpenedStreams.With(prometheus.Labels{"group": cw.monitoredStreams[idx].GroupName}).Dec()
					}
				} else {
					newMonitoredStreams = append(newMonitoredStreams, stream)
				}
			}

			cw.monitoredStreams = newMonitoredStreams
		case <-cw.t.Dying():
			cw.logger.Infof("LogStreamManager for %s is dying, %d alive streams", cw.Config.GroupName, len(cw.monitoredStreams))

			for idx, stream := range cw.monitoredStreams {
				if cw.monitoredStreams[idx].t.Alive() {
					cw.logger.Debugf("killing stream %s", stream.StreamName)
					cw.monitoredStreams[idx].t.Kill(nil)

					if err := cw.monitoredStreams[idx].t.Wait(); err != nil {
						cw.logger.Debugf("error while waiting for death of %s : %s", stream.StreamName, err)
					}
				}
			}

			cw.monitoredStreams = nil
			cw.logger.Debugf("routine cleanup done, return")

			return nil
		}
	}
}

func (cw *CloudwatchSource) TailLogStream(ctx context.Context, cfg *LogStreamTailConfig, outChan chan types.Event) error {
	var startFrom *string

	lastReadMessage := time.Now().UTC()
	ticker := time.NewTicker(cfg.PollStreamInterval)

	// resume at existing index if we already had
	streamIndexMutex.Lock()

	if v := cw.streamIndexes[cfg.GroupName+"+"+cfg.StreamName]; v != "" {
		cfg.logger.Debugf("restarting on index %s", v)
		startFrom = &v
	}

	streamIndexMutex.Unlock()

	for {
		select {
		case <-ticker.C:
			p := cloudwatchlogs.NewGetLogEventsPaginator(
				cw.cwClient,
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
					cw.streamIndexes[cfg.GroupName+"+"+cfg.StreamName] = *startFrom
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

					if cw.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.CloudWatchDatasourceLinesRead.With(prometheus.Labels{
							"group": cfg.GroupName, "stream": cfg.StreamName,
							"datasource_type": "cloudwatch", "acquis_type": evt.Line.Labels["type"],
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

func (cw *CloudwatchSource) ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	cw.logger = logger

	dsn = strings.TrimPrefix(dsn, cw.GetName()+"://")

	args := strings.Split(dsn, "?")
	if len(args) != 2 {
		return errors.New("query is mandatory (at least start_date and end_date or backlog)")
	}

	frags := strings.Split(args[0], ":")
	if len(frags) != 2 {
		return errors.New("cloudwatch path must contain group and stream : /my/group/name:stream/name")
	}

	cw.Config.GroupName = frags[0]
	cw.Config.StreamName = &frags[1]
	cw.Config.Labels = labels
	cw.Config.UniqueId = uuid

	u, err := url.ParseQuery(args[1])
	if err != nil {
		return fmt.Errorf("while parsing %s: %w", dsn, err)
	}

	for k, v := range u {
		switch k {
		case "log_level":
			if len(v) != 1 {
				return errors.New("expected zero or one value for 'log_level'")
			}

			lvl, err := log.ParseLevel(v[0])
			if err != nil {
				return fmt.Errorf("unknown level %s: %w", v[0], err)
			}

			cw.logger.Logger.SetLevel(lvl)
		case "profile":
			if len(v) != 1 {
				return errors.New("expected zero or one value for 'profile'")
			}

			awsprof := v[0]
			cw.Config.AwsProfile = &awsprof
			cw.logger.Debugf("profile set to '%s'", *cw.Config.AwsProfile)
		case "start_date":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'start_date'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			strdate, startDate := parser.GenDateParse(v[0])
			cw.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			cw.Config.StartTime = &startDate
		case "end_date":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'end_date'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			strdate, endDate := parser.GenDateParse(v[0])
			cw.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			cw.Config.EndTime = &endDate
		case "backlog":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'backlog'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			duration, err := time.ParseDuration(v[0])
			if err != nil {
				return fmt.Errorf("unable to parse '%s' as duration: %w", v[0], err)
			}

			cw.logger.Debugf("parsed '%s' as '%s'", v[0], duration)
			start := time.Now().UTC().Add(-duration)
			cw.Config.StartTime = &start
			end := time.Now().UTC()
			cw.Config.EndTime = &end
		default:
			return fmt.Errorf("unexpected argument %s", k)
		}
	}

	cw.logger.Tracef("host=%s", cw.Config.GroupName)
	cw.logger.Tracef("stream=%s", *cw.Config.StreamName)
	cw.Config.GetLogEventsPagesLimit = &def_GetLogEventsPagesLimit

	if err := cw.newClient(ctx); err != nil {
		return err
	}

	if cw.Config.StreamName == nil || cw.Config.GroupName == "" {
		return errors.New("missing stream or group name")
	}

	if cw.Config.StartTime == nil || cw.Config.EndTime == nil {
		return errors.New("start_date and end_date or backlog are mandatory in one-shot mode")
	}

	cw.Config.Mode = configuration.CAT_MODE
	cw.streamIndexes = make(map[string]string)
	cw.t = &tomb.Tomb{}

	return nil
}

func (cw *CloudwatchSource) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	// StreamName string, Start time.Time, End time.Time
	config := LogStreamTailConfig{
		GroupName:              cw.Config.GroupName,
		StreamName:             *cw.Config.StreamName,
		StartTime:              *cw.Config.StartTime,
		EndTime:                *cw.Config.EndTime,
		GetLogEventsPagesLimit: *cw.Config.GetLogEventsPagesLimit,
		logger: cw.logger.WithFields(log.Fields{
			"group":  cw.Config.GroupName,
			"stream": *cw.Config.StreamName,
		}),
		Labels:     cw.Config.Labels,
		ExpectMode: types.TIMEMACHINE,
	}

	return cw.CatLogStream(ctx, &config, out)
}

func (cw *CloudwatchSource) CatLogStream(ctx context.Context, cfg *LogStreamTailConfig, outChan chan types.Event) error {
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
				cw.cwClient,
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
		case <-cw.t.Dying():
			cfg.logger.Warningf("cat stream killed")
			return nil
		}
	}

	cfg.logger.Tracef("CatLogStream out")

	return nil
}

func cwLogToEvent(log cwTypes.OutputLogEvent, cfg *LogStreamTailConfig) (types.Event, error) {
	l := types.Line{}
	evt := types.MakeEvent(cfg.ExpectMode == types.TIMEMACHINE, types.LOG, true)
	if log.Message == nil {
		return evt, errors.New("nil message")
	}

	msg := *log.Message
	if cfg.PrependCloudwatchTimestamp != nil && *cfg.PrependCloudwatchTimestamp {
		eventTimestamp := time.Unix(0, *log.Timestamp*int64(time.Millisecond))
		msg = eventTimestamp.String() + " " + msg
	}

	l.Raw = msg
	l.Labels = cfg.Labels
	l.Time = time.Now().UTC()
	l.Src = fmt.Sprintf("%s/%s", cfg.GroupName, cfg.StreamName)
	l.Process = true
	l.Module = "cloudwatch"
	evt.Line = l
	cfg.logger.Debugf("returned event labels : %+v", evt.Line.Labels)

	return evt, nil
}
