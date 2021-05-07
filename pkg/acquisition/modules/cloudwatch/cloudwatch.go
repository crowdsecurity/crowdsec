package cloudwatchacquisition

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
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
}

//CloudwatchSourceConfiguration allows user to define one or more streams to monitor within a cloudwatch log group
type CloudwatchSourceConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	GroupName                         string         `yaml:"group_name"`              //the group name to be monitored
	StreamPrefix                      *string        `yaml:"stream_prefix,omitempty"` //allow to filter specific streams
	StreamName                        *string        `yaml:"-"`
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
	Mode                              string         `yaml:"-"`
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
	def_GetLogEventsPagesLimit  = int64(1000)
	def_Mode                    = configuration.TAIL_MODE
)

func (cw *CloudwatchSource) Configure(cfg []byte, logger *log.Entry) error {
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	cwConfig := CloudwatchSourceConfiguration{}
	err := yaml.UnmarshalStrict(cfg, &cwConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse CloudwatchSource configuration")
	}
	cw.Config = cwConfig
	cw.logger = logger.WithField("group", cw.Config.GroupName)
	cw.Config.Mode = configuration.TAIL_MODE
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
	return nil
}

func (cw *CloudwatchSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	var sess *session.Session
	cw.t = t
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
	cw.cwClient = cloudwatchlogs.New(sess)
	if cw.cwClient == nil {
		return fmt.Errorf("failed to create cloudwatch client")
	}
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
	cw.logger.Infof("Starting to watch group")
	ticker := time.NewTicker(*cw.Config.PollNewStreamInterval)
	var startFrom *string

	for {
		select {
		case <-cw.t.Dying():
			cw.logger.Infof("stopping group watch")
			return nil
		/*TODO test one specific stream only*/
		case <-ticker.C:
			hasMoreStreams := true
			startFrom = nil
			for hasMoreStreams {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				//there can be a lot of streams in a group, and we're only interested in those recently written to, so we sort by LastEventTime
				err := cw.cwClient.DescribeLogStreamsPagesWithContext(
					ctx,
					&cloudwatchlogs.DescribeLogStreamsInput{
						LogGroupName:        aws.String(cw.Config.GroupName),
						Descending:          aws.Bool(true),
						LogStreamNamePrefix: cw.Config.StreamPrefix,
						NextToken:           startFrom,
						OrderBy:             aws.String(cloudwatchlogs.OrderByLastEventTime),
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
				cancel()
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
	pollDeadStreamInterval := time.NewTicker(10 * time.Second)

	for {
		select {
		case newStream := <-in:
			shouldCreate := true
			cw.logger.Tracef("received new streams to monitor : %s/%s", newStream.GroupName, newStream.StreamName)
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
					return TailLogStream(&newStream, outChan, cw.cwClient)
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
						cw.logger.Debugf("error while waiting for death of %s", stream.StreamName)
					}
				} else {
					cw.monitoredStreams = append(cw.monitoredStreams[:idx], cw.monitoredStreams[idx+1:]...)
				}
			}
			return nil
		}
	}
}

func TailLogStream(cfg *LogStreamTailConfig, outChan chan types.Event, cwClient *cloudwatchlogs.CloudWatchLogs) error {
	var startFrom *string
	var lastReadMessage time.Time = time.Now()
	ticker := time.NewTicker(cfg.PollStreamInterval)

	/*during first run, we want to avoid reading any message, but just get a token.
	if we don't, we might end up sending the same item several times. hence the 'startup' hack */
	startup := true
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
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := cwClient.GetLogEventsPagesWithContext(ctx,
					&cloudwatchlogs.GetLogEventsInput{
						Limit:         aws.Int64(limit),
						LogGroupName:  aws.String(cfg.GroupName),
						LogStreamName: aws.String(cfg.StreamName),
						NextToken:     startFrom,
					},
					func(page *cloudwatchlogs.GetLogEventsOutput, lastPage bool) bool {
						startFrom = page.NextForwardToken
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
								cfg.logger.Warningf("discard event : %s", err)
							}
							cfg.logger.Debugf("pushing message : %s", evt.Line.Raw)
							outChan <- evt
						}
						return true
					},
				)
				cancel()
				if err != nil {
					//cfg.logger.Errorf("got error while getting logs : %s", err)
					newerr := errors.Wrapf(err, "while reading %s/%s", cfg.GroupName, cfg.StreamName)
					cfg.logger.Warningf("err : %s", newerr)
					return newerr
				}
				if startup {
					startup = false
				}
				cfg.logger.Tracef("done reading GetLogEventsPagesWithContext")

				if time.Now().Sub(lastReadMessage) > cfg.StreamReadTimeout {
					cfg.logger.Warningf("%s/%s reached timeout (%s) (last message was %s)", cfg.GroupName, cfg.StreamName, time.Now().Sub(lastReadMessage),
						lastReadMessage)
					return nil
				}
			}
		case <-cfg.t.Dying():
			cfg.logger.Infof("Tail of %s/%s is stopping", cfg.GroupName, cfg.StreamName)
			return fmt.Errorf("killed")
		}
	}
}

func (cw *CloudwatchSource) ConfigureByDSN(dsn string, logtype string, logger *log.Entry) error {
	cw.logger = logger
	u, err := url.Parse(dsn)
	if err != nil {
		return errors.Wrapf(err, "while parsing %s", dsn)
	}
	cw.Config.GroupName = u.Host
	cw.logger.Tracef("host=%s", cw.Config.GroupName)
	cw.Config.StreamName = &u.Path
	cw.logger.Tracef("stream=%s", *cw.Config.StreamName)
	for k, v := range u.Query() {
		switch k {
		case "profile":
			if len(v) != 1 {
				return fmt.Errorf("expected zero or one value for 'profile'")
			}
			awsprof := v[0]
			cw.Config.AwsProfile = &awsprof
			cw.logger.Debugf("profile set to '%s'", cw.Config.AwsProfile)
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
			start := time.Now().UTC().Add(duration)
			cw.Config.StartTime = &start
			end := time.Now().UTC()
			cw.Config.EndTime = &end
		default:
			return fmt.Errorf("unexpected argument %s", k)
		}
	}
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
	cw.cwClient = cloudwatchlogs.New(sess)
	if cw.cwClient == nil {
		return fmt.Errorf("failed to create cloudwatch client")
	}
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
	}
	return CatLogStream(&config, out, cw.cwClient)
}

func CatLogStream(cfg *LogStreamTailConfig, outChan chan types.Event, cwClient *cloudwatchlogs.CloudWatchLogs) error {
	var startFrom *string

	/*convert the times*/
	startTime := cfg.StartTime.Unix() * 1000
	endTime := cfg.EndTime.Unix() * 1000
	hasMoreEvents := true
	for hasMoreEvents {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := cwClient.GetLogEventsPagesWithContext(ctx,
			&cloudwatchlogs.GetLogEventsInput{
				Limit:         aws.Int64(cfg.GetLogEventsPagesLimit),
				LogGroupName:  aws.String(cfg.GroupName),
				LogStreamName: aws.String(cfg.StreamName),
				StartTime:     aws.Int64(startTime),
				EndTime:       aws.Int64(endTime),
				NextToken:     startFrom,
			},
			func(page *cloudwatchlogs.GetLogEventsOutput, lastPage bool) bool {
				for _, event := range page.Events {
					evt, err := cwLogToEvent(event, cfg)
					if err != nil {
						cfg.logger.Warningf("discard event : %s", err)
					}
					cfg.logger.Debugf("pushing message : %s", evt.Line.Raw)
					outChan <- evt
				}
				if page.NextForwardToken == startFrom {
					cfg.logger.Debugf("reached end of available events")
					hasMoreEvents = false
				}
				return true
			},
		)
		cancel()
		if err != nil {
			return errors.Wrapf(err, "while reading logs from %s/%s", cfg.GroupName, cfg.StreamName)
		}
	}
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
	//l.Module = "cloudwatch"
	evt.Line = l
	evt.Process = true
	evt.Type = types.LOG
	evt.ExpectMode = cfg.ExpectMode
	return evt, nil
}
