package cloudwatchacquisition

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
)

/*
 test plan :
	- start on bad group/bad stream
	- start on good settings (oneshot) -> check expected messages
	- start on good settings (stream) -> check expected messages within given time
	- check shutdown/restart
*/

func deleteAllLogGroups(t *testing.T, cw *CloudwatchSource) {
	input := &cloudwatchlogs.DescribeLogGroupsInput{}
	result, err := cw.cwClient.DescribeLogGroups(input)
	require.NoError(t, err)
	for _, group := range result.LogGroups {
		_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
			LogGroupName: group.LogGroupName,
		})
		require.NoError(t, err)
	}
}

func checkForLocalStackAvailability() error {
	v := os.Getenv("AWS_ENDPOINT_FORCE")
	if v == "" {
		return fmt.Errorf("missing aws endpoint for tests : AWS_ENDPOINT_FORCE")
	}

	v = strings.TrimPrefix(v, "http://")

	_, err := net.Dial("tcp", v)
	if err != nil {
		return fmt.Errorf("while dialing %s : %s : aws endpoint isn't available", v, err)
	}

	return nil
}

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		os.Exit(0)
	}
	if err := checkForLocalStackAvailability(); err != nil {
		log.Fatalf("local stack error : %s", err)
	}
	def_PollNewStreamInterval = 1 * time.Second
	def_PollStreamInterval = 1 * time.Second
	def_StreamReadTimeout = 10 * time.Second
	def_MaxStreamAge = 5 * time.Second
	def_PollDeadStreamInterval = 5 * time.Second
	os.Exit(m.Run())
}

func TestWatchLogGroupForStreams(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetLevel(log.DebugLevel)
	tests := []struct {
		config              []byte
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		setup               func(*testing.T, *CloudwatchSource)
		run                 func(*testing.T, *CloudwatchSource)
		teardown            func(*testing.T, *CloudwatchSource)
		expectedResLen      int
		expectedResMessages []string
	}{
		// require a group name that doesn't exist
		{
			name: "group_does_not_exists",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: b
stream_name: test_stream`),
			expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group_not_used_1"),
				})
				require.NoError(t, err)
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group_not_used_1"),
				})
				require.NoError(t, err)
			},
		},
		// test stream mismatch
		{
			name: "group_exists_bad_stream_name",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_name: test_stream_bad`),
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen: 0,
		},
		// test stream mismatch
		{
			name: "group_exists_bad_stream_regexp",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_regexp: test_bad[0-9]+`),
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen: 0,
		},
		// require a group name that does exist and contains a stream in which we are going to put events
		{
			name: "group_exists_stream_exists_has_events",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`),
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
				_, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen:      3,
			expectedResMessages: []string{"test_message_1", "test_message_4", "test_message_5"},
		},
		// have a stream generate events, reach time-out and gets polled again
		{
			name: "group_exists_stream_exists_has_events+timeout",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`),
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
				_, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen:      3,
			expectedResMessages: []string{"test_message_1", "test_message_41", "test_message_51"},
		},
		// have a stream generate events, reach time-out and dead body collection
		{
			name: "group_exists_stream_exists_has_events+timeout+GC",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_log_group1
log_level: trace
stream_name: test_stream`),
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// have a message before we start - won't be popped, but will trigger stream monitoring
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
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
				time.Sleep(def_PollDeadStreamInterval + (1 * time.Second))
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dbgLogger := log.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(log.DebugLevel)
			dbgLogger.Infof("starting test")
			cw := CloudwatchSource{}
			err := cw.Configure(tc.config, dbgLogger)
			cstest.RequireErrorContains(t, err, tc.expectedCfgErr)

			if tc.expectedCfgErr != "" {
				return
			}

			// run pre-routine : tests use it to set group & streams etc.
			if tc.setup != nil {
				tc.setup(t, &cw)
			}
			out := make(chan types.Event)
			tmb := tomb.Tomb{}
			var rcvdEvts []types.Event

			dbgLogger.Infof("running StreamingAcquisition")
			actmb := tomb.Tomb{}
			actmb.Go(func() error {
				err := cw.StreamingAcquisition(out, &actmb)
				dbgLogger.Infof("acquis done")
				cstest.RequireErrorContains(t, err, tc.expectedStartErr)
				return nil
			})

			// let's empty output chan
			tmb.Go(func() error {
				for {
					select {
					case in := <-out:
						log.Debugf("received event %+v", in)
						rcvdEvts = append(rcvdEvts, in)
					case <-tmb.Dying():
						log.Debugf("pumper died")
						return nil
					}
				}
			})

			if tc.run != nil {
				tc.run(t, &cw)
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
			// dbgLogger.Infof("collected events : %d -> %+v", len(rcvd_evts), rcvd_evts)
			// check results
			if tc.expectedResLen != -1 {
				if tc.expectedResLen != len(rcvdEvts) {
					t.Fatalf("%s : expected %d results got %d -> %v", tc.name, tc.expectedResLen, len(rcvdEvts), rcvdEvts)
				}
				dbgLogger.Debugf("got %d expected messages", len(rcvdEvts))
			}
			if len(tc.expectedResMessages) != 0 {
				res := tc.expectedResMessages
				for idx, v := range rcvdEvts {
					if len(res) == 0 {
						t.Fatalf("result %d/%d : received '%s', didn't expect anything (recvd:%d, expected:%d)", idx, len(rcvdEvts), v.Line.Raw, len(rcvdEvts), len(tc.expectedResMessages))
					}
					if res[0] != v.Line.Raw {
						t.Fatalf("result %d/%d : expected '%s', received '%s' (recvd:%d, expected:%d)", idx, len(rcvdEvts), res[0], v.Line.Raw, len(rcvdEvts), len(tc.expectedResMessages))
					}
					dbgLogger.Debugf("got message '%s'", res[0])
					res = res[1:]
				}
				if len(res) != 0 {
					t.Fatalf("leftover unmatched results : %v", res)
				}

			}
			if tc.teardown != nil {
				tc.teardown(t, &cw)
			}
		})
	}
}

func TestConfiguration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetLevel(log.DebugLevel)
	tests := []struct {
		config           []byte
		expectedCfgErr   string
		expectedStartErr string
		name             string
	}{
		{
			name: "group_does_not_exists",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group
stream_name: test_stream`),
			expectedStartErr: "The specified log group does not exist",
		},
		{
			config: []byte(`
xxx: cloudwatch
labels:
  type: test_source
group_name: test_group
stream_name: test_stream`),
			expectedCfgErr: "field xxx not found in type",
		},
		{
			name: "missing_group_name",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
stream_name: test_stream`),
			expectedCfgErr: "group_name is mandatory for CloudwatchSource",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dbgLogger := log.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(log.DebugLevel)
			cw := CloudwatchSource{}
			err := cw.Configure(tc.config, dbgLogger)
			cstest.RequireErrorContains(t, err, tc.expectedCfgErr)
			if tc.expectedCfgErr != "" {
				return
			}

			out := make(chan types.Event)
			tmb := tomb.Tomb{}

			switch cw.GetMode() {
			case "tail":
				err = cw.StreamingAcquisition(out, &tmb)
			case "cat":
				err = cw.OneShotAcquisition(out, &tmb)
			}

			cstest.RequireErrorContains(t, err, tc.expectedStartErr)

			log.Debugf("killing ...")
			tmb.Kill(nil)
			<-tmb.Dead()
			log.Debugf("dead :)")
		})
	}
}

func TestConfigureByDSN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetLevel(log.DebugLevel)
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dbgLogger := log.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(log.DebugLevel)
			cw := CloudwatchSource{}
			err := cw.ConfigureByDSN(tc.dsn, tc.labels, dbgLogger, "")
			cstest.RequireErrorContains(t, err, tc.expectedCfgErr)
		})
	}
}

func TestOneShotAcquisition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetLevel(log.DebugLevel)
	tests := []struct {
		dsn                 string
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		setup               func(*testing.T, *CloudwatchSource)
		run                 func(*testing.T, *CloudwatchSource)
		teardown            func(*testing.T, *CloudwatchSource)
		expectedResLen      int
		expectedResMessages []string
	}{
		// stream with no data
		{
			name: "empty_stream",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen: 0,
		},
		// stream with one event
		{
			name: "get_one_event",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			// expectedStartErr: "The specified log group does not exist",
			setup: func(t *testing.T, cw *CloudwatchSource) {
				deleteAllLogGroups(t, cw)
				_, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)

				_, err = cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
				require.NoError(t, err)

				// this one is too much in the back
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(2 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)

				// this one can be read
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						{
							Message:   aws.String("test_message_2"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)

				// this one is in the past
				_, err = cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						{
							Message:   aws.String("test_message_3"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(3 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				})
				require.NoError(t, err)
			},
			teardown: func(t *testing.T, cw *CloudwatchSource) {
				_, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				require.NoError(t, err)
			},
			expectedResLen:      1,
			expectedResMessages: []string{"test_message_2"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dbgLogger := log.New().WithField("test", tc.name)
			dbgLogger.Logger.SetLevel(log.DebugLevel)
			dbgLogger.Infof("starting test")
			cw := CloudwatchSource{}
			err := cw.ConfigureByDSN(tc.dsn, map[string]string{"type": "test"}, dbgLogger, "")
			cstest.RequireErrorContains(t, err, tc.expectedCfgErr)
			if tc.expectedCfgErr != "" {
				return
			}

			dbgLogger.Infof("config done test")
			// run pre-routine : tests use it to set group & streams etc.
			if tc.setup != nil {
				tc.setup(t, &cw)
			}
			out := make(chan types.Event, 100)
			tmb := tomb.Tomb{}
			var rcvdEvts []types.Event

			dbgLogger.Infof("running StreamingAcquisition")
			err = cw.OneShotAcquisition(out, &tmb)
			dbgLogger.Infof("acquis done")
			cstest.RequireErrorContains(t, err, tc.expectedStartErr)
			close(out)
			// let's empty output chan
			for evt := range out {
				rcvdEvts = append(rcvdEvts, evt)
			}

			if tc.run != nil {
				tc.run(t, &cw)
			} else {
				dbgLogger.Warning("no code to run")
			}
			if tc.expectedResLen != -1 {
				if tc.expectedResLen != len(rcvdEvts) {
					t.Fatalf("%s : expected %d results got %d -> %v", tc.name, tc.expectedResLen, len(rcvdEvts), rcvdEvts)
				} else {
					dbgLogger.Debugf("got %d expected messages", len(rcvdEvts))
				}
			}
			if len(tc.expectedResMessages) != 0 {
				res := tc.expectedResMessages
				for idx, v := range rcvdEvts {
					if len(res) == 0 {
						t.Fatalf("result %d/%d : received '%s', didn't expect anything (recvd:%d, expected:%d)", idx, len(rcvdEvts), v.Line.Raw, len(rcvdEvts), len(tc.expectedResMessages))
					}
					if res[0] != v.Line.Raw {
						t.Fatalf("result %d/%d : expected '%s', received '%s' (recvd:%d, expected:%d)", idx, len(rcvdEvts), res[0], v.Line.Raw, len(rcvdEvts), len(tc.expectedResMessages))
					}
					dbgLogger.Debugf("got message '%s'", res[0])
					res = res[1:]
				}
				if len(res) != 0 {
					t.Fatalf("leftover unmatched results : %v", res)
				}

			}
			if tc.teardown != nil {
				tc.teardown(t, &cw)
			}
		})
	}
}
