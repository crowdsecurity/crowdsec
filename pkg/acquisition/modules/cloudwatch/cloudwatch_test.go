package cloudwatchacquisition

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

/*
 test plan :
	- start on bad group/bad stream
	- start on good settings (oneshot) -> check expected messages
	- start on good settings (stream) -> check expected messages within given time
	- check shutdown/restart
*/

func createLogGroup(t *testing.T, ctx context.Context, cw *CloudwatchSource, group string) {
	_, err := cw.cwClient.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(group),
	})
	require.NoError(t, err)
}

func createLogStream(t *testing.T, ctx context.Context, cw *CloudwatchSource, group string, stream string) {
	_, err := cw.cwClient.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(group),
		LogStreamName: aws.String(stream),
	})
	require.NoError(t, err)
}

func deleteAllLogGroups(t *testing.T, ctx context.Context, cw *CloudwatchSource) {
	input := &cloudwatchlogs.DescribeLogGroupsInput{}
	result, err := cw.cwClient.DescribeLogGroups(ctx, input)
	require.NoError(t, err)

	for _, group := range result.LogGroups {
		_, err := cw.cwClient.DeleteLogGroup(ctx, &cloudwatchlogs.DeleteLogGroupInput{
			LogGroupName: group.LogGroupName,
		})
		require.NoError(t, err)
	}
}

type CloudwatchSuite struct {
	suite.Suite
}

func (*CloudwatchSuite) SetupSuite() {
	def_PollNewStreamInterval = 1 * time.Second
	def_PollStreamInterval = 1 * time.Second
	def_StreamReadTimeout = 10 * time.Second
	def_MaxStreamAge = 5 * time.Second
	def_PollDeadStreamInterval = 5 * time.Second
}

func TestCloudwatchSuite(t *testing.T) {
	cstest.SetAWSTestEnv(t)
	suite.Run(t, new(CloudwatchSuite))
}

func (s *CloudwatchSuite) TestWatchLogGroupForStreams() {
	logrus.SetLevel(logrus.DebugLevel)

	ctx := s.T().Context()

	tests := []struct {
		config              string
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		setup               func(*testing.T, *CloudwatchSource)
		run                 func(*testing.T, *CloudwatchSource)
		teardown            func(*testing.T, *CloudwatchSource)
		expectedResMessages []string
	}{
		// require a group name that doesn't exist
		{
			name: "group_does_not_exist",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: b
stream_name: test_stream`,
			expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_group_not_used_1")
			},
		},
		// test stream mismatch
		{
			name: "group_exists_bad_stream_name",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_name: test_stream_bad`,
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_group1")
				createLogStream(t, ctx, cw, "test_group1", "test_stream")

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			expectedResMessages: []string{},
		},
		// test stream mismatch
		{
			name: "group_exists_bad_stream_regexp",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_regexp: test_bad[0-9]+`,
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_group1")
				createLogStream(t, ctx, cw, "test_group1", "test_stream")

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			expectedResMessages: []string{},
		},
		// require a group name that does exist and contains a stream in which we are going to put events
		{
			name: "group_exists_stream_exists_has_events",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`,
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_log_group1")
				createLogStream(t, ctx, cw, "test_log_group1", "test_stream")

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, cw *CloudwatchSource) {
				// wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				_, err := cw.cwClient.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_4"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
						// and add an event in the future that will be popped
						{
							Message:   aws.String("test_message_5"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			expectedResMessages: []string{"test_message_1", "test_message_4", "test_message_5"},
		},
		// have a stream generate events, reach time-out and gets polled again
		{
			name: "group_exists_stream_exists_has_events+timeout",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`,
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_log_group1")
				createLogStream(t, ctx, cw, "test_log_group1", "test_stream")

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, cw *CloudwatchSource) {
				// wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				// send some events
				_, err := cw.cwClient.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_41"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
				// wait for the stream to time-out
				time.Sleep(def_StreamReadTimeout + (1 * time.Second))
				// and send events again
				_, err = cw.cwClient.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_51"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
				// wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
			},
			expectedResMessages: []string{"test_message_1", "test_message_41", "test_message_51"},
		},
		// have a stream generate events, reach time-out and dead body collection
		{
			name: "group_exists_stream_exists_has_events+timeout+GC",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`,
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_log_group1")
				createLogStream(t, ctx, cw, "test_log_group1", "test_stream")

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			run: func(_ *testing.T, _ *CloudwatchSource) {
				// wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				time.Sleep(def_PollDeadStreamInterval + (1 * time.Second))
			},
			expectedResMessages: []string{"test_message_1"},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			dbgLogger := logrus.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(logrus.DebugLevel)
			dbgLogger.Infof("starting test")

			cw := CloudwatchSource{}
			err := cw.Configure(ctx, []byte(tc.config), dbgLogger, metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(s.T(), err, tc.expectedCfgErr)

			if tc.expectedCfgErr != "" {
				return
			}

			// run pre-routine : tests use it to set group & streams etc.
			if tc.setup != nil {
				tc.setup(s.T(), &cw)
			}

			out := make(chan types.Event)
			tmb := tomb.Tomb{}

			dbgLogger.Infof("running StreamingAcquisition")

			actmb := tomb.Tomb{}
			actmb.Go(func() error {
				err := cw.StreamingAcquisition(ctx, out, &actmb)

				dbgLogger.Infof("acquis done")
				cstest.RequireErrorContains(s.T(), err, tc.expectedStartErr)

				return nil
			})

			got := []string{}

			// let's empty output chan
			tmb.Go(func() error {
				for {
					select {
					case in := <-out:
						dbgLogger.Debugf("received event %+v", in)
						got = append(got, in.Line.Raw)
					case <-tmb.Dying():
						dbgLogger.Debug("pumper died")
						return nil
					}
				}
			})

			if tc.run != nil {
				tc.run(s.T(), &cw)
			} else {
				dbgLogger.Warning("no code to run")
			}

			time.Sleep(5 * time.Second)
			dbgLogger.Infof("killing collector")
			tmb.Kill(nil)
			<-tmb.Dead()
			dbgLogger.Infof("killing datasource")
			actmb.Kill(nil)
			<-actmb.Dead()

			if len(tc.expectedResMessages) == 0 {
				s.Empty(got, "unexpected events")
			} else {
				s.Equal(tc.expectedResMessages, got, "mismatched events")
			}

			if tc.teardown != nil {
				tc.teardown(s.T(), &cw)
			}
		})
	}
}

func (s *CloudwatchSuite) TestConfiguration() {
	logrus.SetLevel(logrus.DebugLevel)

	ctx := s.T().Context()

	tests := []struct {
		config           string
		expectedCfgErr   string
		expectedStartErr string
		name             string
	}{
		{
			name: "group_does_not_exist",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group
stream_name: test_stream`,
			expectedStartErr: "The specified log group does not exist",
		},
		{
			config: `
xxx: cloudwatch
labels:
  type: test_source
group_name: test_group
stream_name: test_stream`,
			expectedCfgErr: `[2:1] unknown field "xxx"`,
		},
		{
			name: "missing_group_name",
			config: `
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
stream_name: test_stream`,
			expectedCfgErr: "group_name is mandatory for CloudwatchSource",
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			dbgLogger := logrus.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(logrus.DebugLevel)

			cw := CloudwatchSource{}
			err := cw.Configure(ctx, []byte(tc.config), dbgLogger, metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(s.T(), err, tc.expectedCfgErr)

			if tc.expectedCfgErr != "" {
				return
			}

			out := make(chan types.Event)
			tmb := tomb.Tomb{}

			switch cw.GetMode() {
			case "tail":
				err = cw.StreamingAcquisition(ctx, out, &tmb)
			case "cat":
				err = cw.OneShotAcquisition(ctx, out, &tmb)
			}

			cstest.RequireErrorContains(s.T(), err, tc.expectedStartErr)

			dbgLogger.Debugf("killing ...")
			tmb.Kill(nil)
			<-tmb.Dead()
			dbgLogger.Debugf("dead :)")
		})
	}
}

func (s *CloudwatchSuite) TestConfigureByDSN() {
	logrus.SetLevel(logrus.DebugLevel)

	ctx := s.T().Context()

	tests := []struct {
		dsn            string
		labels         map[string]string
		expectedCfgErr string
		name           string
	}{
		{
			name:           "missing_query",
			dsn:            "cloudwatch://bad_log_group:bad_stream_name",
			expectedCfgErr: "query is mandatory (at least start_date and end_date or backlog)",
		},
		{
			name: "backlog",
			dsn:  "cloudwatch://bad_log_group:bad_stream_name?backlog=30m&log_level=info&profile=test",
			// expectedCfgErr: "query is mandatory (at least start_date and end_date or backlog)",
		},
		{
			name: "start_date/end_date",
			dsn:  "cloudwatch://bad_log_group:bad_stream_name?start_date=2021/05/15 14:04&end_date=2021/05/15 15:04",
			// expectedCfgErr: "query is mandatory (at least start_date and end_date or backlog)",
		},
		{
			name:           "bad_log_level",
			dsn:            "cloudwatch://bad_log_group:bad_stream_name?backlog=4h&log_level=",
			expectedCfgErr: "unknown level : not a valid logrus Level: ",
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			dbgLogger := logrus.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(logrus.DebugLevel)

			cw := CloudwatchSource{}
			err := cw.ConfigureByDSN(ctx, tc.dsn, tc.labels, dbgLogger, "")
			cstest.RequireErrorContains(s.T(), err, tc.expectedCfgErr)
		})
	}
}

func (s *CloudwatchSuite) TestOneShotAcquisition() {
	logrus.SetLevel(logrus.DebugLevel)

	ctx := s.T().Context()

	tests := []struct {
		dsn                 string
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		setup               func(*testing.T, *CloudwatchSource)
		run                 func(*testing.T, *CloudwatchSource)
		teardown            func(*testing.T, *CloudwatchSource)
		expectedResMessages []string
	}{
		// stream with no data
		{
			name: "empty_stream",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_log_group1")
				createLogStream(t, ctx, cw, "test_log_group1", "test_stream")
			},
			expectedResMessages: []string{},
		},
		// stream with one event
		{
			name: "get_one_event",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, ctx, cw)
				createLogGroup(t, ctx, cw, "test_log_group1")
				createLogStream(t, ctx, cw, "test_log_group1", "test_stream")

				// this one is too much in the back
				_, err := cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(2 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)

				// this one can be read
				_, err = cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_2"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)

				// this one is in the past
				_, err = cw.cwClient.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []cwTypes.InputLogEvent{
						{
							Message:   aws.String("test_message_3"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(3 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)

				// prevent flaky test due to slow CI
				end := time.Now().UTC().Add(5 * time.Second)
				cw.Config.EndTime = &end
			},
			expectedResMessages: []string{"test_message_2"},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			dbgLogger := logrus.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(logrus.DebugLevel)
			dbgLogger.Infof("starting test")

			cw := CloudwatchSource{}
			err := cw.ConfigureByDSN(ctx, tc.dsn, map[string]string{"type": "test"}, dbgLogger, "")
			cstest.RequireErrorContains(s.T(), err, tc.expectedCfgErr)

			if tc.expectedCfgErr != "" {
				return
			}

			dbgLogger.Infof("config done test")
			// run pre-routine : tests use it to set group & streams etc.
			if tc.setup != nil {
				tc.setup(s.T(), &cw)
			}

			out := make(chan types.Event, 100)
			tmb := tomb.Tomb{}

			dbgLogger.Infof("running OneShotAcquisition")

			err = cw.OneShotAcquisition(ctx, out, &tmb)
			cstest.RequireErrorContains(s.T(), err, tc.expectedStartErr)
			dbgLogger.Infof("acquis done")

			close(out)
			// let's empty output chan
			got := []string{}
			for evt := range out {
				got = append(got, evt.Line.Raw)
			}

			if tc.run != nil {
				tc.run(s.T(), &cw)
			} else {
				dbgLogger.Warning("no code to run")
			}

			if len(tc.expectedResMessages) == 0 {
				s.Empty(got, "unexpected events")
			} else {
				s.Equal(tc.expectedResMessages, got, "mismatched events")
			}

			if tc.teardown != nil {
				tc.teardown(s.T(), &cw)
			}
		})
	}
}
