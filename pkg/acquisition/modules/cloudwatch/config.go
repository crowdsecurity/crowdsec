package cloudwatchacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

// Configuration allows user to define one or more streams to monitor within a cloudwatch log group
type Configuration struct {
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

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{}
	if err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("cannot parse CloudwatchSource configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.Config.GroupName == "" {
		return errors.New("group_name is mandatory for CloudwatchSource")
	}

	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}

	if s.Config.DescribeLogStreamsLimit == nil {
		s.Config.DescribeLogStreamsLimit = &def_DescribeLogStreamsLimit
	}

	if s.Config.PollNewStreamInterval == nil {
		s.Config.PollNewStreamInterval = &def_PollNewStreamInterval
	}

	if s.Config.MaxStreamAge == nil {
		s.Config.MaxStreamAge = &def_MaxStreamAge
	}

	if s.Config.PollStreamInterval == nil {
		s.Config.PollStreamInterval = &def_PollStreamInterval
	}

	if s.Config.StreamReadTimeout == nil {
		s.Config.StreamReadTimeout = &def_StreamReadTimeout
	}

	if s.Config.GetLogEventsPagesLimit == nil {
		s.Config.GetLogEventsPagesLimit = &def_GetLogEventsPagesLimit
	}

	if s.Config.AwsApiCallTimeout == nil {
		s.Config.AwsApiCallTimeout = &def_AwsApiCallTimeout
	}

	if s.Config.AwsConfigDir == nil {
		s.Config.AwsConfigDir = &def_AwsConfigDir
	}

	return nil
}

func (s *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.metricsLevel = metricsLevel

	s.logger = logger.WithField("group", s.Config.GroupName)

	s.logger.Debugf("Starting configuration for Cloudwatch group %s", s.Config.GroupName)
	s.logger.Tracef("describelogstreams_limit set to %d", *s.Config.DescribeLogStreamsLimit)
	s.logger.Tracef("poll_new_stream_interval set to %v", *s.Config.PollNewStreamInterval)
	s.logger.Tracef("max_stream_age set to %v", *s.Config.MaxStreamAge)
	s.logger.Tracef("poll_stream_interval set to %v", *s.Config.PollStreamInterval)
	s.logger.Tracef("stream_read_timeout set to %v", *s.Config.StreamReadTimeout)
	s.logger.Tracef("getlogeventspages_limit set to %v", *s.Config.GetLogEventsPagesLimit)
	s.logger.Tracef("aws_api_timeout set to %v", *s.Config.AwsApiCallTimeout)

	if *s.Config.MaxStreamAge > *s.Config.StreamReadTimeout {
		s.logger.Warningf("max_stream_age > stream_read_timeout, stream might keep being opened/closed")
	}

	s.logger.Tracef("aws_config_dir set to %s", *s.Config.AwsConfigDir)

	if *s.Config.AwsConfigDir != "" {
		_, err := os.Stat(*s.Config.AwsConfigDir)
		if err != nil {
			s.logger.Errorf("can't read aws_config_dir '%s' got err %s", *s.Config.AwsConfigDir, err)
			return fmt.Errorf("can't read aws_config_dir %s got err %w ", *s.Config.AwsConfigDir, err)
		}

		os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
		// as aws sdk relies on $HOME, let's allow the user to override it :)
		os.Setenv("AWS_CONFIG_FILE", fmt.Sprintf("%s/config", *s.Config.AwsConfigDir))
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", fmt.Sprintf("%s/credentials", *s.Config.AwsConfigDir))
	} else {
		if s.Config.AwsRegion == "" {
			s.logger.Errorf("aws_region is not specified, specify it or aws_config_dir")
			return errors.New("aws_region is not specified, specify it or aws_config_dir")
		}

		os.Setenv("AWS_REGION", s.Config.AwsRegion)
	}

	if err := s.newClient(ctx); err != nil {
		return err
	}

	s.streamIndexes = make(map[string]string)

	targetStream := "*"

	if s.Config.StreamRegexp != nil {
		if _, err := regexp.Compile(*s.Config.StreamRegexp); err != nil {
			return fmt.Errorf("while compiling regexp '%s': %w", *s.Config.StreamRegexp, err)
		}

		targetStream = *s.Config.StreamRegexp
	} else if s.Config.StreamName != nil {
		targetStream = *s.Config.StreamName
	}

	s.logger.Infof("Adding cloudwatch group '%s' (stream:%s) to datasources", s.Config.GroupName, targetStream)

	return nil
}

func (s *Source) ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	s.logger = logger

	dsn = strings.TrimPrefix(dsn, s.GetName()+"://")

	args := strings.Split(dsn, "?")
	if len(args) != 2 {
		return errors.New("query is mandatory (at least start_date and end_date or backlog)")
	}

	frags := strings.Split(args[0], ":")
	if len(frags) != 2 {
		return errors.New("cloudwatch path must contain group and stream : /my/group/name:stream/name")
	}

	s.Config.GroupName = frags[0]
	s.Config.StreamName = &frags[1]
	s.Config.Labels = labels
	s.Config.UniqueId = uuid

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

			s.logger.Logger.SetLevel(lvl)
		case "profile":
			if len(v) != 1 {
				return errors.New("expected zero or one value for 'profile'")
			}

			awsprof := v[0]
			s.Config.AwsProfile = &awsprof
			s.logger.Debugf("profile set to '%s'", *s.Config.AwsProfile)
		case "start_date":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'start_date'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			strdate, startDate := parser.GenDateParse(v[0])
			s.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			s.Config.StartTime = &startDate
		case "end_date":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'end_date'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			strdate, endDate := parser.GenDateParse(v[0])
			s.logger.Debugf("parsed '%s' as '%s'", v[0], strdate)
			s.Config.EndTime = &endDate
		case "backlog":
			if len(v) != 1 {
				return errors.New("expected zero or one argument for 'backlog'")
			}
			// let's reuse our parser helper so that a ton of date formats are supported
			duration, err := time.ParseDuration(v[0])
			if err != nil {
				return fmt.Errorf("unable to parse '%s' as duration: %w", v[0], err)
			}

			s.logger.Debugf("parsed '%s' as '%s'", v[0], duration)
			start := time.Now().UTC().Add(-duration)
			s.Config.StartTime = &start
			end := time.Now().UTC()
			s.Config.EndTime = &end
		default:
			return fmt.Errorf("unexpected argument %s", k)
		}
	}

	s.logger.Tracef("host=%s", s.Config.GroupName)
	s.logger.Tracef("stream=%s", *s.Config.StreamName)
	s.Config.GetLogEventsPagesLimit = &def_GetLogEventsPagesLimit

	if err := s.newClient(ctx); err != nil {
		return err
	}

	if s.Config.StreamName == nil || s.Config.GroupName == "" {
		return errors.New("missing stream or group name")
	}

	if s.Config.StartTime == nil || s.Config.EndTime == nil {
		return errors.New("start_date and end_date or backlog are mandatory in one-shot mode")
	}

	s.Config.Mode = configuration.CAT_MODE
	s.streamIndexes = make(map[string]string)
	s.t = &tomb.Tomb{}

	return nil
}
