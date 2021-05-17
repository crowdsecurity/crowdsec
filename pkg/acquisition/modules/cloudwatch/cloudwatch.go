package cloudwatchacquisition

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
)

//CloudwatchSource is the runtime instance keeping track of N streams within 1 cloudwatch group
type CloudwatchSource struct {
	Config CloudwatchSourceConfiguration
	/*runtime stuff*/
	logger           *log.Entry
	t                *tomb.Tomb
	cwClient         *cloudwatchlogs.CloudWatchLogs
	monitoredStreams []*LogStreamTailConfig
	streamIndexes    map[string]string
}

//CloudwatchSourceConfiguration allows user to define one or more streams to monitor within a cloudwatch log group
type CloudwatchSourceConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	GroupName                         string         `yaml:"group_name"`              //the group name to be monitored
	StreamRegexp                      *string        `yaml:"stream_regexp,omitempty"` //allow to filter specific streams
	StreamName                        *string        `yaml:"stream_name,omitempty"`
	StartTime, EndTime                *time.Time     `yaml:"-"`
	DescribeLogStreamsLimit           *int64         `yaml:"describelogstreams_limit,omitempty"` //batch size for DescribeLogStreamsPagesWithContext
	GetLogEventsPagesLimit            *int64         `yaml:"getlogeventspages_limit,omitempty"`
	PollNewStreamInterval             *time.Duration `yaml:"poll_new_stream_interval,omitempty"` //frequency at which we poll for new streams within the log group
	MaxStreamAge                      *time.Duration `yaml:"max_stream_age,omitempty"`           //monitor only streams that have been updated within $duration
	PollStreamInterval                *time.Duration `yaml:"poll_stream_interval,omitempty"`     //frequency at which we poll each stream
	StreamReadTimeout                 *time.Duration `yaml:"stream_read_timeout,omitempty"`      //stop monitoring streams that haven't been updated within $duration, might be reopened later tho
	AwsApiCallTimeout                 *time.Duration `yaml:"aws_api_timeout,omitempty"`
	AwsProfile                        *string        `yaml:"aws_profile,omitempty"`
	PrependCloudwatchTimestamp        *bool          `yaml:"prepend_cloudwatch_timestamp,omitempty"`
}

//LogStreamTailConfig is the configuration for one given stream within one group
type LogStreamTailConfig struct {
	GroupName                  string
	StreamName                 string
	GetLogEventsPagesLimit     int64
	PollStreamInterval         time.Duration
	StreamReadTimeout          time.Duration
	PrependCloudwatchTimestamp *bool
	Labels                     map[string]string
	logger                     *log.Entry
	ExpectMode                 int
	t                          tomb.Tomb
	StartTime, EndTime         time.Time //only used for CatMode
}

var (
	def_DescribeLogStreamsLimit = int64(50)
	def_PollNewStreamInterval   = 10 * time.Second
	def_MaxStreamAge            = 5 * time.Minute
	def_PollStreamInterval      = 10 * time.Second
	def_AwsApiCallTimeout       = 10 * time.Second
	def_StreamReadTimeout       = 10 * time.Minute
	def_PollDeadStreamInterval  = 10 * time.Second
	def_GetLogEventsPagesLimit  = int64(1000)
)

func (cw *CloudwatchSource) Configure(cfg []byte, logger *log.Entry) error {
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	cwConfig := CloudwatchSourceConfiguration{}
	err := yaml.UnmarshalStrict(cfg, &cwConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse CloudwatchSource configuration")
	}
	/*
		TBD: Acquisition returned error : while describing group acquis-cloudwatch-tests: InvalidParameterException: Cannot order by LastEventTime with a logStreamNamePrefix.
		either we sort by time or by prefix, can't do both :()
	*/
	cw.Config = cwConfig
	cw.logger = logger.WithField("group", cw.Config.GroupName)
	if cw.Config.Mode == "" {
		cw.Config.Mode = configuration.TAIL_MODE
	}
	logger.Debugf("Starting configuration for Cloudwatch group %s", cw.Config.GroupName)
	if len(cw.Config.GroupName) == 0 {
		return fmt.Errorf("group_name is mandatory for CloudwatchSource")
	}
	if cw.Config.DescribeLogStreamsLimit == nil {
		cw.Config.DescribeLogStreamsLimit = &def_DescribeLogStreamsLimit
	}
	logger.Tracef("DescribeLogStreamsLimit set to %d", *cw.Config.DescribeLogStreamsLimit)
	if cw.Config.PollNewStreamInterval == nil {
		cw.Config.PollNewStreamInterval = &def_PollNewStreamInterval
	}
	logger.Tracef("PollNewStreamInterval set to %v", *cw.Config.PollNewStreamInterval)
	if cw.Config.MaxStreamAge == nil {
		cw.Config.MaxStreamAge = &def_MaxStreamAge
	}
	logger.Tracef("MaxStreamAge set to %v", *cw.Config.MaxStreamAge)
	if cw.Config.PollStreamInterval == nil {
		cw.Config.PollStreamInterval = &def_PollStreamInterval
	}
	logger.Tracef("PollStreamInterval set to %v", *cw.Config.PollStreamInterval)
	if cw.Config.StreamReadTimeout == nil {
		cw.Config.StreamReadTimeout = &def_StreamReadTimeout
	}
	logger.Tracef("StreamReadTimeout set to %v", *cw.Config.StreamReadTimeout)
	if cw.Config.GetLogEventsPagesLimit == nil {
		cw.Config.GetLogEventsPagesLimit = &def_GetLogEventsPagesLimit
	}
	logger.Tracef("GetLogEventsPagesLimit set to %v", *cw.Config.GetLogEventsPagesLimit)
	if cw.Config.AwsApiCallTimeout == nil {
		cw.Config.AwsApiCallTimeout = &def_AwsApiCallTimeout
	}
	logger.Tracef("AwsApiCallTimeout set to %v", *cw.Config.AwsApiCallTimeout)
	if *cw.Config.MaxStreamAge > *cw.Config.StreamReadTimeout {
		logger.Warningf("MaxStreamAge > StreamReadTimeout, stream might keep being opened/closed")
	}
	if err := cw.newClient(); err != nil {
		return err
	}
	cw.streamIndexes = make(map[string]string)
	return nil
}

func (cw *CloudwatchSource) newClient() error {
	var sess *session.Session

	if cw.Config.AwsProfile != nil {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Profile:           *cw.Config.AwsProfile,
		}))
	} else {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
	}

	if sess == nil {
		return fmt.Errorf("failed to create aws session")
	}
	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		cw.logger.Debugf("[testing] overloading endpoint with %s", v)
		cw.cwClient = cloudwatchlogs.New(sess, aws.NewConfig().WithEndpoint(v))
	} else {
		cw.cwClient = cloudwatchlogs.New(sess)
	}
	if cw.cwClient == nil {
		return fmt.Errorf("failed to create cloudwatch client")
	}
	return nil
}

func (cw *CloudwatchSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	cw.t = t
	monitChan := make(chan LogStreamTailConfig)
	t.Go(func() error {
		return cw.LogStreamManager(monitChan, out)
	})
	return cw.WatchLogGroupForStreams(monitChan)
}

func (cw *CloudwatchSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (cw *CloudwatchSource) GetMode() string {
	return cw.Config.Mode
}

func (cw *CloudwatchSource) GetName() string {
	return "cloudwatch"
}

func (cw *CloudwatchSource) CanRun() error {
	return nil
}

func (cw *CloudwatchSource) Dump() interface{} {
	return cw
}

func (cw *CloudwatchSource) WatchLogGroupForStreams(out chan LogStreamTailConfig) error {
	cw.logger.Debugf("Starting to watch group (interval:%s)", cw.Config.PollNewStreamInterval)
	ticker := time.NewTicker(*cw.Config.PollNewStreamInterval)
	var startFrom *string

	for {
		select {
		case <-cw.t.Dying():
			cw.logger.Infof("stopping group watch")
			return nil
		case <-ticker.C:
			hasMoreStreams := true
			startFrom = nil
			for hasMoreStreams {
				ctx := context.Background()
				//there can be a lot of streams in a group, and we're only interested in those recently written to, so we sort by LastEventTime
				err := cw.cwClient.DescribeLogStreamsPagesWithContext(
					ctx,
					&cloudwatchlogs.DescribeLogStreamsInput{
						LogGroupName: aws.String(cw.Config.GroupName),
						Descending:   aws.Bool(true),
						NextToken:    startFrom,
						OrderBy:      aws.String(cloudwatchlogs.OrderByLastEventTime),
						Limit:        cw.Config.DescribeLogStreamsLimit,
					},
					func(page *cloudwatchlogs.DescribeLogStreamsOutput, lastPage bool) bool {
						for _, event := range page.LogStreams {
							startFrom = page.NextToken
							//we check if the stream has been written to recently enough to be monitored
							if event.LastIngestionTime != nil {
								//aws uses millisecond since the epoch
								oldest := time.Now().UTC().Add(-*cw.Config.MaxStreamAge)
								LastIngestionTime := time.Unix(0, *event.LastIngestionTime*int64(time.Millisecond))
								if LastIngestionTime.Before(oldest) {
									cw.logger.Tracef("stop iteration, %s reached oldest age, stop (%s < %s)", *event.LogStreamName, LastIngestionTime, time.Now().Add(-*cw.Config.MaxStreamAge))
									hasMoreStreams = false
									return false
								}
								cw.logger.Tracef("stream %s is elligible for monitoring", *event.LogStreamName)
								//the stream has been update recently, check if we should monitor it
								monitorStream := LogStreamTailConfig{
									GroupName:                  cw.Config.GroupName,
									StreamName:                 *event.LogStreamName,
									GetLogEventsPagesLimit:     *cw.Config.GetLogEventsPagesLimit,
									PollStreamInterval:         *cw.Config.PollStreamInterval,
									StreamReadTimeout:          *cw.Config.StreamReadTimeout,
									PrependCloudwatchTimestamp: cw.Config.PrependCloudwatchTimestamp,
									ExpectMode:                 leaky.LIVE,
									Labels:                     cw.Config.Labels,
								}
								out <- monitorStream
							}
						}
						if lastPage {
							cw.logger.Tracef("reached last page")
							hasMoreStreams = false
						}
						return true
					},
				)
				if err != nil {
					newerr := errors.Wrapf(err, "while describing group %s", cw.Config.GroupName)
					return newerr
				}
			}
		}
	}
}

//LogStreamManager receives the potential streams to monitor, and start a go routine when needed
func (cw *CloudwatchSource) LogStreamManager(in chan LogStreamTailConfig, outChan chan types.Event) error {

	cw.logger.Debugf("starting to monitor streams for %s", cw.Config.GroupName)
	pollDeadStreamInterval := time.NewTicker(def_PollDeadStreamInterval)

	for {
		select {
		case newStream := <-in:
			shouldCreate := true
			cw.logger.Tracef("received new streams to monitor : %s/%s", newStream.GroupName, newStream.StreamName)

			if cw.Config.StreamName != nil && newStream.StreamName != *cw.Config.StreamName {
				cw.logger.Tracef("stream %s != %s", newStream.StreamName, *cw.Config.StreamName)
				continue
			}

			if cw.Config.StreamRegexp != nil {
				match, err := regexp.Match(newStream.StreamName, []byte(*cw.Config.StreamRegexp))
				if err != nil {
					cw.logger.Warningf("invalid regexp : %s", err)
				} else {
					if !match {
						cw.logger.Tracef("stream %s doesn't match %s", newStream.StreamName, *cw.Config.StreamRegexp)
						continue
					}
				}
			}

			for idx, stream := range cw.monitoredStreams {
				if newStream.GroupName == stream.GroupName && newStream.StreamName == stream.StreamName {
					//stream exists, but is dead, remove it from list
					if !stream.t.Alive() {
						cw.logger.Debugf("stream %s already exists, but is dead", newStream.StreamName)
						cw.monitoredStreams = append(cw.monitoredStreams[:idx], cw.monitoredStreams[idx+1:]...)
						break
					}
					shouldCreate = false
					break
				}
			}

			//let's start watching this stream
			if shouldCreate {
				newStream.t = tomb.Tomb{}
				newStream.logger = cw.logger.WithFields(log.Fields{"stream": newStream.StreamName})
				cw.logger.Debugf("starting tail of stream %s", newStream.StreamName)
				newStream.t.Go(func() error {
					return cw.TailLogStream(&newStream, outChan)
				})
				cw.monitoredStreams = append(cw.monitoredStreams, &newStream)
			}
		case <-pollDeadStreamInterval.C:
			for idx, stream := range cw.monitoredStreams {
				if !cw.monitoredStreams[idx].t.Alive() {
					cw.monitoredStreams = append(cw.monitoredStreams[:idx], cw.monitoredStreams[idx+1:]...)
					cw.logger.Debugf("remove dead stream %s", stream.StreamName)
					break
				}
			}
		case <-cw.t.Dying():
			cw.logger.Infof("LogStreamManager for %s is dying, %d alive streams", cw.Config.GroupName, len(cw.monitoredStreams))
			for idx, stream := range cw.monitoredStreams {
				if cw.monitoredStreams[idx].t.Alive() {
					cw.logger.Debugf("killing stream %s", stream.StreamName)
					cw.monitoredStreams[idx].t.Kill(nil)
					if err := cw.monitoredStreams[idx].t.Wait(); err != nil {
						cw.logger.Debugf("error while waiting for death of %s : %s", stream.StreamName, err)
					}
				} else {
					cw.monitoredStreams = append(cw.monitoredStreams[:idx], cw.monitoredStreams[idx+1:]...)
				}
			}
			cw.logger.Debugf("routine cleanup done, return")
			return nil
		}
	}
}

func (cw *CloudwatchSource) TailLogStream(cfg *LogStreamTailConfig, outChan chan types.Event) error {
	var startFrom *string
	var lastReadMessage time.Time = time.Now()
	startup := true

	ticker := time.NewTicker(cfg.PollStreamInterval)
	//resume at existing index if we already had
	if v, ok := cw.streamIndexes[cfg.GroupName+"+"+cfg.StreamName]; ok && v != "" {
		cfg.logger.Debugf("restarting on index %s", v)
		startFrom = &v
		startup = false
	}
	/*during first run, we want to avoid reading any message, but just get a token.
	if we don't, we might end up sending the same item several times. hence the 'startup' hack */
	for {
		select {
		case <-ticker.C:
			cfg.logger.Tracef("entering loop")
			hasMorePages := true
			for hasMorePages {
				/*for the first call, we only consume the last item*/
				limit := cfg.GetLogEventsPagesLimit
				if startup {
					limit = 1
				}
				cfg.logger.Tracef("calling GetLogEventsPagesWithContext")
				ctx := context.Background()
				err := cw.cwClient.GetLogEventsPagesWithContext(ctx,
					&cloudwatchlogs.GetLogEventsInput{
						Limit:         aws.Int64(limit),
						LogGroupName:  aws.String(cfg.GroupName),
						LogStreamName: aws.String(cfg.StreamName),
						NextToken:     startFrom,
					},
					func(page *cloudwatchlogs.GetLogEventsOutput, lastPage bool) bool {
						cfg.logger.Tracef("%d results, last:%t", len(page.Events), lastPage)
						startFrom = page.NextForwardToken
						if page.NextForwardToken != nil {
							cw.streamIndexes[cfg.GroupName+"+"+cfg.StreamName] = *page.NextForwardToken
						}
						if startup { //we grab the NextForwardToken and we return on first iteration
							return false
						}
						if lastPage { /*wait another ticker to check on new log availability*/
							cfg.logger.Tracef("last page")
							hasMorePages = false
						}
						if len(page.Events) > 0 {
							lastReadMessage = time.Now()
						}
						for _, event := range page.Events {
							evt, err := cwLogToEvent(event, cfg)
							if err != nil {
								cfg.logger.Warningf("cwLogToEvent error, discarded event : %s", err)
							} else {
								cfg.logger.Debugf("pushing message : %s", evt.Line.Raw)
								outChan <- evt
							}
						}
						return true
					},
				)
				if err != nil {
					newerr := errors.Wrapf(err, "while reading %s/%s", cfg.GroupName, cfg.StreamName)
					cfg.logger.Warningf("err : %s", newerr)
					return newerr
				}
				if startup {
					startup = false
				}
				cfg.logger.Tracef("done reading GetLogEventsPagesWithContext")

				if time.Since(lastReadMessage) > cfg.StreamReadTimeout {
					cfg.logger.Infof("%s/%s reached timeout (%s) (last message was %s)", cfg.GroupName, cfg.StreamName, time.Since(lastReadMessage),
						lastReadMessage)
					return nil
				}
			}
		case <-cfg.t.Dying():
			cfg.logger.Infof("logstream tail stopping")
			return fmt.Errorf("killed")
		}
	}
}

func (cw *CloudwatchSource) ConfigureByDSN(dsn string, logtype string, logger *log.Entry) error {
	cw.logger = logger

	dsn = strings.TrimPrefix(dsn, cw.GetName()+"://")
	args := strings.Split(dsn, "?")
	if len(args) != 2 {
		return fmt.Errorf("query is mandatory (at least start_date and end_date or backlog)")
	}
	frags := strings.Split(args[0], ":")
	if len(frags) != 2 {
		return fmt.Errorf("cloudwatch path must contain group and stream : /my/group/name:stream/name")
	}
	cw.Config.GroupName = frags[0]
	cw.Config.StreamName = &frags[1]
	cw.Config.Labels = make(map[string]string)
	cw.Config.Labels["type"] = logtype

	u, err := url.ParseQuery(args[1])
	if err != nil {
		return errors.Wrapf(err, "while parsing %s", dsn)
	}

	for k, v := range u {
		switch k {
		case "log_level":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one value for 'log_level'")
			}
			lvl, err := log.ParseLevel(v[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", v[0])
			}
			cw.logger.Logger.SetLevel(lvl)

		case "profile":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one value for 'profile'")
			}
			awsprof := v[0]
			cw.Config.AwsProfile = &awsprof
			cw.logger.Debugf("profile set to '%s'", *cw.Config.AwsProfile)
		case "start_date":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one argument for 'start_date'")
			}
			//let's reuse our parser helper so that a ton of date formats are supported
			strdate, startDate := parser.GenDateParse(v[0])
			cw.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			cw.Config.StartTime = &startDate
		case "end_date":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one argument for 'end_date'")
			}
			//let's reuse our parser helper so that a ton of date formats are supported
			strdate, endDate := parser.GenDateParse(v[0])
			cw.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			cw.Config.EndTime = &endDate
		case "backlog":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one argument for 'backlog'")
			}
			//let's reuse our parser helper so that a ton of date formats are supported
			duration, err := time.ParseDuration(v[0])
			if err != nil {
				return errors.Wrapf(err, "unable to parse '%s' as duration", v[0])
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

	if err := cw.newClient(); err != nil {
		return err
	}

	if cw.Config.StreamName == nil || cw.Config.GroupName == "" {
		return fmt.Errorf("missing stream or group name")
	}
	if cw.Config.StartTime == nil || cw.Config.EndTime == nil {
		return fmt.Errorf("start_date and end_date or backlog are mandatory in one-shot mode")
	}

	cw.Config.Mode = configuration.CAT_MODE
	cw.streamIndexes = make(map[string]string)
	cw.t = &tomb.Tomb{}
	return nil
}

func (cw *CloudwatchSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	//StreamName string, Start time.Time, End time.Time
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
		ExpectMode: leaky.TIMEMACHINE,
	}
	return cw.CatLogStream(&config, out)
}

func (cw *CloudwatchSource) CatLogStream(cfg *LogStreamTailConfig, outChan chan types.Event) error {
	var startFrom *string
	var head = true
	/*convert the times*/
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
			ctx := context.Background()
			err := cw.cwClient.GetLogEventsPagesWithContext(ctx,
				&cloudwatchlogs.GetLogEventsInput{
					Limit:         aws.Int64(10),
					LogGroupName:  aws.String(cfg.GroupName),
					LogStreamName: aws.String(cfg.StreamName),
					StartTime:     aws.Int64(startTime),
					EndTime:       aws.Int64(endTime),
					StartFromHead: &head,
					NextToken:     startFrom,
				},
				func(page *cloudwatchlogs.GetLogEventsOutput, lastPage bool) bool {
					cfg.logger.Tracef("in GetLogEventsPagesWithContext handker (%d events) (last:%t)", len(page.Events), lastPage)
					for _, event := range page.Events {
						evt, err := cwLogToEvent(event, cfg)
						if err != nil {
							cfg.logger.Warningf("discard event : %s", err)
						}
						cfg.logger.Debugf("pushing message : %s", evt.Line.Raw)
						outChan <- evt
					}
					if startFrom != nil && *page.NextForwardToken == *startFrom {
						cfg.logger.Debugf("reached end of available events")
						hasMoreEvents = false
						return false
					}
					startFrom = page.NextForwardToken
					return true
				},
			)
			if err != nil {
				return errors.Wrapf(err, "while reading logs from %s/%s", cfg.GroupName, cfg.StreamName)
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

func cwLogToEvent(log *cloudwatchlogs.OutputLogEvent, cfg *LogStreamTailConfig) (types.Event, error) {
	l := types.Line{}
	evt := types.Event{}
	if log.Message == nil {
		return evt, fmt.Errorf("nil message")
	}
	msg := *log.Message
	if cfg.PrependCloudwatchTimestamp != nil && *cfg.PrependCloudwatchTimestamp {
		eventTimestamp := time.Unix(0, *log.Timestamp*int64(time.Millisecond))
		msg = eventTimestamp.String() + " " + msg
	}

	l.Raw = msg
	l.Labels = cfg.Labels
	l.Time = time.Now()
	l.Src = fmt.Sprintf("%s/%s", cfg.GroupName, cfg.StreamName)
	l.Process = true
	l.Module = "cloudwatch"
	evt.Line = l
	evt.Process = true
	evt.Type = types.LOG
	evt.ExpectMode = cfg.ExpectMode
	cfg.logger.Debugf("returned event labels : %+v", evt.Line.Labels)
	return evt, nil
}
