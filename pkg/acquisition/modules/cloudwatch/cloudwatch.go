package cloudwatchacquisition

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
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
	t                tomb.Tomb
	cwClient         *cloudwatchlogs.CloudWatchLogs
	monitoredStreams []LogStreamTailConfig
}

//CloudwatchSourceConfiguration allows user to define one or more streams to monitor within a cloudwatch log group
type CloudwatchSourceConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	GroupName                         string         `yaml:"group_name"`                         //the group name to be monitored
	StreamPrefix                      *string        `yaml:"stream_prefix,omitempty"`            //allow to filter specific streams
	DescribeLogStreamsLimit           *int64         `yaml:"describelogstreams_limit,omitempty"` //batch size for DescribeLogStreamsPagesWithContext
	GetLogEventsPagesLimit            *int64         `yaml:"getlogeventspages_limit,omitpempty"`
	PollNewStreamInterval             *time.Duration `yaml:"poll_new_stream_interval,omitempty"` //frequency at which we poll for new streams within the log group
	MaxStreamAge                      *time.Duration `yaml:"max_stream_age,omitempty"`           //monitor only streams that have been updated within $duration
	PollStreamInterval                *time.Duration `yaml:"poll_stream_interval,omitempty"`     //frequency at which we poll each stream
	StreamReadTimeout                 *time.Duration `yaml:"stream_read_timeout,omitempty"`      //stop monitoring streams that haven't been updated within $duration, might be reopened later tho
	AwsApiCallTimeout                 *time.Duration `yaml:"aws_api_timeout,omitempty"`
}

//LogStreamTailConfig is the configuration for one given stream within one group
type LogStreamTailConfig struct {
	GroupName                  string
	StreamName                 string
	GetLogEventsPagesLimit     int64
	PollStreamInterval         time.Duration
	StreamReadTimeout          time.Duration
	PrependCloudwatchTimestamp bool
	Labels                     map[string]string
	logger                     *log.Entry
	ExpectMode                 int
	t                          tomb.Tomb
}

var def_DescribeLogStreamsLimit = int64(50)
var def_PollNewStreamInterval = 10 * time.Second
var def_MaxStreamAge = 5 * time.Minute
var def_PollStreamInterval = 10 * time.Second
var def_AwsApiCallTimeout = 10 * time.Second

var def_StreamReadTimeout = 10 * time.Minute
var def_GetLogEventsPagesLimit = int64(1000)

func (cw *CloudwatchSource) Configure(cfg []byte, logger *log.Entry) error {
	cw.logger = logger.WithField("group", cw.Config.GroupName)
	cwConfig := CloudwatchSourceConfiguration{}
	err := yaml.UnmarshalStrict(cfg, &cwConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse CloudwatchSource configuration")
	}
	cw.Config = cwConfig
	logger.Debugf("Starting configuration for Cloudwatch group %s", cw.Config.GroupName)
	cw.t = tomb.Tomb{}
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
	return nil
}

func (cw *CloudwatchSource) StreamingAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (cw *CloudwatchSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (cw *CloudwatchSource) ConfigureByDSN(string, string, *log.Entry) error {
	return nil
}

func (cw *CloudwatchSource) GetMode() string {
	return configuration.TAIL_MODE
}

func (cw *CloudwatchSource) GetName() string {
	return "cloudwatch"
}

func (cw *CloudwatchSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
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
		case <-ticker.C:
			hasMoreStreams := true
			cw.logger.Tracef("starting outter loop")
			startFrom = nil
			for hasMoreStreams {
				cw.logger.Tracef("starting describe!")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				//there can be a lot of streams in a group, and we're only interested in those recently written to, so we sort by LastEventTime
				cw.cwClient.DescribeLogStreamsPagesWithContext(
					ctx,
					&cloudwatchlogs.DescribeLogStreamsInput{
						LogGroupName:        aws.String(cw.Config.GroupName),
						Descending:          aws.Bool(true),
						LogStreamNamePrefix: cw.Config.StreamPrefix,
						NextToken:           startFrom,
						OrderBy:             aws.String(cloudwatchlogs.OrderByLastEventTime),
					},
					func(page *cloudwatchlogs.DescribeLogStreamsOutput, lastPage bool) bool {
						cw.logger.Tracef("got %d items", len(page.LogStreams))
						for _, event := range page.LogStreams {
							startFrom = page.NextToken
							//we check if the stream has been written to recently enough to be monitored
							if event.LastIngestionTime != nil {
								//aws uses millisecond since the epoch
								oldest := time.Now().UTC().Add(-*cw.Config.MaxStreamAge)
								LastIngestionTime := time.Unix(0, *event.LastIngestionTime*int64(time.Millisecond))
								if oldest.Before(LastIngestionTime) {
									cw.logger.Debugf("stream %s reached oldest age, stop (%s < %s)", *event.LogStreamName, LastIngestionTime, time.Now().Add(-cfg.MaxStreamAge))
									hasMoreStreams = false
									return false
								}
								cw.logger.Debugf("stream %s is elligible for monitoring", *event.LogStreamName)
								//the stream has been update recently, check if we should monitor it
								monitorStream := LogStreamTailConfig{
									GroupName:              cw.Config.GroupName,
									StreamName:             *event.LogStreamName,
									GetLogEventsPagesLimit: *cw.Config.GetLogEventsPagesLimit,
									PollStreamInterval:     *cw.Config.PollStreamInterval,
									StreamReadTimeout:      *cw.Config.StreamReadTimeout,
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
			}
		}
	}
	return nil
}

//LogStreamManager receives the potential streams to monitor, and start a go routine when needed
func (cw *CloudwatchSource) LogStreamManager(in chan LogStreamTailConfig, outChan chan types.Event) error {

	cw.logger.Debugf("starting to monitor streams for %s", cw.Config.GroupName)
	pollDeadStreamInterval := time.NewTicker(10 * time.Second)

	for {
		select {
		case newStream := <-in:
			shouldCreate := true
			cw.logger.Debugf("received new streams to monitor : %s/%s", newStream.GroupName, newStream.StreamName)
			for idx, stream := range cw.monitoredStreams {
				if newStream.GroupName == stream.GroupName && newStream.StreamName == stream.StreamName {
					//stream exists, but is dead, remove it from list
					if !cw.monitoredStreams[idx].t.Alive() {
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
					return TailLogStream(newStream, outChan, cw.cwClient)
				})
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
				if !cw.monitoredStreams[idx].t.Alive() {
					cw.monitoredStreams = append(cw.monitoredStreams[:idx], cw.monitoredStreams[idx+1:]...)
					cw.logger.Debugf("remove dead stream %s", stream.StreamName)
					break
				}
			}
		}
	}
	return nil
}

func TailLogStream(cfg LogStreamTailConfig, outChan chan types.Event, cwClient *cloudwatchlogs.CloudWatchLogs) error {
	var startFrom *string
	var lastReadMessage time.Time
	ticker := time.NewTicker(cfg.PollStreamInterval)

	lastReadMessage = time.Now()
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
					startup = false
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
							outChan <- evt
							startFrom = page.NextForwardToken
						}
						return true
					},
				)
				if err != nil {
					cfg.logger.Errorf("got error while getting logs : %s", err)
					newerr := errors.Wrapf(err, "while reading %s/%s", cfg.GroupName, cfg.StreamName)
					cfg.t.Kill(newerr)
					return newerr
				}
				cancel()
				cfg.logger.Tracef("done reading GetLogEventsPagesWithContext")

				if time.Now().Sub(lastReadMessage) > cfg.StreamReadTimeout {
					cfg.logger.Warningf("%s/%s reached timeout (%s, last message was %s)", cfg.GroupName, cfg.StreamName, time.Now().Sub(lastReadMessage),
						lastReadMessage)
					cfg.t.Kill(nil)
					return nil
				}
			}
		case <-cfg.t.Dying():
			cfg.logger.Infof("Tail of %s/%s is stopping", cfg.GroupName, cfg.StreamName)
			return fmt.Errorf("killed")
		}
	}
	return nil
}

func cwLogToEvent(log *cloudwatchlogs.OutputLogEvent, cfg LogStreamTailConfig) (types.Event, error) {
	l := types.Line{}
	evt := types.Event{}
	if log.Message == nil {
		return evt, fmt.Errorf("nil message")
	}
	msg := *log.Message
	if cfg.PrependCloudwatchTimestamp {
		eventTimestamp := time.Unix(0, *log.Timestamp*int64(time.Millisecond))
		msg = eventTimestamp.String() + " " + msg
	}

	l.Raw = msg
	l.Labels = cfg.Labels
	l.Time = time.Now()
	l.Src = fmt.Sprintf("%s/%s", cfg.GroupName, cfg.StreamName)
	l.Process = true
	evt.Line = l
	evt.Process = true
	evt.Type = types.LOG
	evt.ExpectMode = cfg.ExpectMode
	return evt, nil
}
