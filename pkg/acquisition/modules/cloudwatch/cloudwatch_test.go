package cloudwatchacquisition

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

/*
 test plan :
	- start on bad group/bad stream
	- start on good settings (oneshot) -> check expected messages
	- start on good settings (stream) -> check expected messages within given time
	- check shutdown/restart
*/

func checkForLocalStackAvailability() error {
	if v := os.Getenv("AWS_ENDPOINT_FORCE"); v != "" {
		v = strings.TrimPrefix(v, "http://")
		_, err := net.Dial("tcp", v)
		if err != nil {
			return fmt.Errorf("while dialing %s : %s : aws endpoint isn't available", v, err)
		}
	} else {
		return fmt.Errorf("missing aws endpoint for tests : AWS_ENDPOINT_FORCE")
	}
	return nil
}

func TestMain(m *testing.M) {
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
	var err error
	log.SetLevel(log.DebugLevel)
	tests := []struct {
		config              []byte
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		pre                 func(*CloudwatchSource)
		run                 func(*CloudwatchSource)
		post                func(*CloudwatchSource)
		expectedResLen      int
		expectedResMessages []string
	}{
		//require a group name that doesn't exist
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
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group_not_used_1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)
				}
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group_not_used_1"),
				}); err != nil {
					t.Fatalf("failed to delete log group : %s", err)
				}
			},
		},
		//test stream mismatch
		{
			name: "group_exists_bad_stream_name",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_name: test_stream_bad`),
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)
				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to create log stream : %s", err)
				}
				//have a message before we start - won't be popped, but will trigger stream monitoring
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					log.Fatalf("failed to put logs")
				}
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				}); err != nil {
					t.Fatalf("failed to delete log group : %s", err)
				}
			},
			expectedResLen: 0,
		},
		//test stream mismatch
		{
			name: "group_exists_bad_stream_regexp",
			config: []byte(`
source: cloudwatch
aws_region: us-east-1
labels:
  type: test_source
group_name: test_group1
stream_regexp: test_bad[0-9]+`),
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)
				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to create log stream : %s", err)

				}
				//have a message before we start - won't be popped, but will trigger stream monitoring
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs")
				}
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_group1"),
				}); err != nil {
					t.Fatalf("failed to delete log group : %s", err)

				}
			},
			expectedResLen: 0,
		},
		//require a group name that does exist and contains a stream in which we gonna put events
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
			//expectedStartErr: "The specified log group does not exist",
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)

				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to create log stream : %s", err)

				}
				//have a message before we start - won't be popped, but will trigger stream monitoring
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs")
				}
			},
			run: func(cw *CloudwatchSource) {
				//wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_4"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
						//and add an event in the future that will be popped
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_5"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs : %s", err)
				}
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to delete log stream : %s", err)

				}
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to delete log group : %s", err)

				}
			},
			expectedResLen:      3,
			expectedResMessages: []string{"test_message_1", "test_message_4", "test_message_5"},
		},
		//have a stream generate events, reach time-out and gets polled again
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
			//expectedStartErr: "The specified log group does not exist",
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)

				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to create log stream : %s", err)
				}
				//have a message before we start - won't be popped, but will trigger stream monitoring
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs")
				}
			},
			run: func(cw *CloudwatchSource) {
				//wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				//send some events
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_41"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs : %s", err)
				}
				//wait for the stream to time-out
				time.Sleep(def_StreamReadTimeout + (1 * time.Second))
				//and send events again
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_51"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs : %s", err)
				}
				//wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to delete log stream : %s", err)

				}
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to delete log group : %s", err)

				}
			},
			expectedResLen:      3,
			expectedResMessages: []string{"test_message_1", "test_message_41", "test_message_51"},
		},
		//have a stream generate events, reach time-out and dead body collection
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
			//expectedStartErr: "The specified log group does not exist",
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to create log group : %s", err)
				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to create log stream : %s", err)
				}
				//have a message before we start - won't be popped, but will trigger stream monitoring
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					t.Fatalf("failed to put logs")
				}
			},
			run: func(cw *CloudwatchSource) {
				//wait for new stream pickup + stream poll interval
				time.Sleep(def_PollNewStreamInterval + (1 * time.Second))
				time.Sleep(def_PollStreamInterval + (1 * time.Second))
				time.Sleep(def_PollDeadStreamInterval + (1 * time.Second))
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogStream(&cloudwatchlogs.DeleteLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("failed to delete log stream : %s", err)

				}
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to delete log stream : %s", err)

				}
			},
			expectedResLen: 1,
		},
	}

	for _, test := range tests {
		dbgLogger := log.New().WithField("test", test.name)
		dbgLogger.Logger.SetLevel(log.DebugLevel)
		dbgLogger.Infof("starting test")
		cw := CloudwatchSource{}
		err = cw.Configure(test.config, dbgLogger)
		if err != nil && test.expectedCfgErr != "" {
			if !strings.Contains(err.Error(), test.expectedCfgErr) {
				t.Fatalf("%s expected error '%s' got error '%s'", test.name, test.expectedCfgErr, err.Error())
			}
			log.Debugf("got expected error : %s", err)
			continue
		} else if err != nil && test.expectedCfgErr == "" {
			t.Fatalf("%s unexpected error : %s", test.name, err)
			continue
		} else if test.expectedCfgErr != "" && err == nil {
			t.Fatalf("%s expected error '%s', got none", test.name, test.expectedCfgErr)
			continue
		}
		dbgLogger.Infof("config done test")
		//run pre-routine : tests use it to set group & streams etc.
		if test.pre != nil {
			test.pre(&cw)
		}
		out := make(chan types.Event)
		tmb := tomb.Tomb{}
		var rcvd_evts []types.Event

		dbgLogger.Infof("running StreamingAcquisition")
		actmb := tomb.Tomb{}
		actmb.Go(func() error {
			err := cw.StreamingAcquisition(out, &actmb)
			dbgLogger.Infof("acquis done")

			if err != nil && test.expectedStartErr != "" && !strings.Contains(err.Error(), test.expectedStartErr) {
				t.Fatalf("%s expected error '%s' got '%s'", test.name, test.expectedStartErr, err.Error())
			} else if err != nil && test.expectedStartErr == "" {
				t.Fatalf("%s unexpected error '%s'", test.name, err)
			} else if err == nil && test.expectedStartErr != "" {
				t.Fatalf("%s expected error '%s' got none", test.name, err)
			}
			return nil
		})

		//let's empty output chan
		tmb.Go(func() error {
			for {
				select {
				case in := <-out:
					log.Debugf("received event %+v", in)
					rcvd_evts = append(rcvd_evts, in)
				case <-tmb.Dying():
					log.Debugf("pumper died")
					return nil
				}
			}
		})

		if test.run != nil {
			test.run(&cw)
		} else {
			dbgLogger.Warning("no run code")
		}

		time.Sleep(5 * time.Second)
		dbgLogger.Infof("killing collector")
		tmb.Kill(nil)
		<-tmb.Dead()
		dbgLogger.Infof("killing datasource")
		actmb.Kill(nil)
		<-actmb.Dead()
		//dbgLogger.Infof("collected events : %d -> %+v", len(rcvd_evts), rcvd_evts)
		//check results
		if test.expectedResLen != -1 {
			if test.expectedResLen != len(rcvd_evts) {
				t.Fatalf("%s : expected %d results got %d -> %v", test.name, test.expectedResLen, len(rcvd_evts), rcvd_evts)
			}
			dbgLogger.Debugf("got %d expected messages", len(rcvd_evts))
		}
		if len(test.expectedResMessages) != 0 {
			res := test.expectedResMessages
			for idx, v := range rcvd_evts {
				if len(res) == 0 {
					t.Fatalf("result %d/%d : received '%s', didn't expect anything (recvd:%d, expected:%d)", idx, len(rcvd_evts), v.Line.Raw, len(rcvd_evts), len(test.expectedResMessages))
				}
				if res[0] != v.Line.Raw {
					t.Fatalf("result %d/%d : expected '%s', received '%s' (recvd:%d, expected:%d)", idx, len(rcvd_evts), res[0], v.Line.Raw, len(rcvd_evts), len(test.expectedResMessages))
				}
				dbgLogger.Debugf("got message '%s'", res[0])
				res = res[1:]
			}
			if len(res) != 0 {
				t.Fatalf("leftover unmatched results : %v", res)
			}

		}
		if test.post != nil {
			test.post(&cw)
		}
	}
}

func TestConfiguration(t *testing.T) {
	var err error
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

	for idx, test := range tests {
		dbgLogger := log.New().WithField("test", test.name)
		dbgLogger.Logger.SetLevel(log.DebugLevel)
		log.Printf("%d/%d", idx, len(tests))
		cw := CloudwatchSource{}
		err = cw.Configure(test.config, dbgLogger)
		if err != nil && test.expectedCfgErr != "" {
			if !strings.Contains(err.Error(), test.expectedCfgErr) {
				t.Fatalf("%s expected error '%s' got error '%s'", test.name, test.expectedCfgErr, err.Error())
			}
			log.Debugf("got expected error : %s", err)
			continue
		} else if err != nil && test.expectedCfgErr == "" {
			t.Fatalf("%s unexpected error : %s", test.name, err)
			continue
		} else if test.expectedCfgErr != "" && err == nil {
			t.Fatalf("%s expected error '%s', got none", test.name, test.expectedCfgErr)
			continue
		}
		out := make(chan types.Event)
		tmb := tomb.Tomb{}

		switch cw.GetMode() {
		case "tail":
			err = cw.StreamingAcquisition(out, &tmb)
		case "cat":
			err = cw.OneShotAcquisition(out, &tmb)
		}
		if err != nil && test.expectedStartErr != "" && !strings.Contains(err.Error(), test.expectedStartErr) {
			t.Fatalf("%s expected error '%s' got '%s'", test.name, test.expectedStartErr, err.Error())
		} else if err != nil && test.expectedStartErr == "" {
			t.Fatalf("%s unexpected error '%s'", test.name, err)
		} else if err == nil && test.expectedStartErr != "" {
			t.Fatalf("%s expected error '%s' got none", test.name, err)
		}

		log.Debugf("killing ...")
		tmb.Kill(nil)
		<-tmb.Dead()
		log.Debugf("dead :)")

	}
}

func TestConfigureByDSN(t *testing.T) {
	var err error
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
			//expectedCfgErr: "query is mandatory (at least start_date and end_date or backlog)",
		},
		{
			name: "start_date/end_date",
			dsn:  "cloudwatch://bad_log_group:bad_stream_name?start_date=2021/05/15 14:04&end_date=2021/05/15 15:04",
			//expectedCfgErr: "query is mandatory (at least start_date and end_date or backlog)",
		},
		{
			name:           "bad_log_level",
			dsn:            "cloudwatch://bad_log_group:bad_stream_name?backlog=4h&log_level=",
			expectedCfgErr: "unknown level : not a valid logrus Level: ",
		},
	}

	for idx, test := range tests {
		dbgLogger := log.New().WithField("test", test.name)
		dbgLogger.Logger.SetLevel(log.DebugLevel)
		log.Printf("%d/%d", idx, len(tests))
		cw := CloudwatchSource{}
		err = cw.ConfigureByDSN(test.dsn, test.labels, dbgLogger)
		if err != nil && test.expectedCfgErr != "" {
			if !strings.Contains(err.Error(), test.expectedCfgErr) {
				t.Fatalf("%s expected error '%s' got error '%s'", test.name, test.expectedCfgErr, err.Error())
			}
			log.Debugf("got expected error : %s", err)
			continue
		} else if err != nil && test.expectedCfgErr == "" {
			t.Fatalf("%s unexpected error : %s", test.name, err)
			continue
		} else if test.expectedCfgErr != "" && err == nil {
			t.Fatalf("%s expected error '%s', got none", test.name, test.expectedCfgErr)
			continue
		}
	}
}

func TestOneShotAcquisition(t *testing.T) {
	var err error
	log.SetLevel(log.DebugLevel)
	tests := []struct {
		dsn                 string
		expectedCfgErr      string
		expectedStartErr    string
		name                string
		pre                 func(*CloudwatchSource)
		run                 func(*CloudwatchSource)
		post                func(*CloudwatchSource)
		expectedResLen      int
		expectedResMessages []string
	}{
		//stream with no data
		{
			name: "empty_stream",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			//expectedStartErr: "The specified log group does not exist",
			pre: func(cw *CloudwatchSource) {
				cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
				cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				})
			},
			post: func(cw *CloudwatchSource) {
				cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				})
			},
			expectedResLen: 0,
		},
		//stream with one event
		{
			name: "get_one_event",
			dsn:  "cloudwatch://test_log_group1:test_stream?backlog=1h",
			//expectedStartErr: "The specified log group does not exist",
			pre: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("error while CreateLogGroup")
				}
				if _, err := cw.cwClient.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
				}); err != nil {
					t.Fatalf("error while CreateLogStream")

				}
				//this one is too much in the back
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_1"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(2 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					log.Fatalf("failed to put logs")
				}

				//this one can be read
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_2"),
							Timestamp: aws.Int64(time.Now().UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					log.Fatalf("failed to put logs")
				}

				//this one is in the past
				if _, err := cw.cwClient.PutLogEvents(&cloudwatchlogs.PutLogEventsInput{
					LogGroupName:  aws.String("test_log_group1"),
					LogStreamName: aws.String("test_stream"),
					LogEvents: []*cloudwatchlogs.InputLogEvent{
						&cloudwatchlogs.InputLogEvent{
							Message:   aws.String("test_message_3"),
							Timestamp: aws.Int64(time.Now().UTC().Add(-(3 * time.Hour)).UTC().Unix() * 1000),
						},
					},
				}); err != nil {
					log.Fatalf("failed to put logs")
				}
			},
			post: func(cw *CloudwatchSource) {
				if _, err := cw.cwClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{
					LogGroupName: aws.String("test_log_group1"),
				}); err != nil {
					t.Fatalf("failed to delete")
				}
			},
			expectedResLen:      1,
			expectedResMessages: []string{"test_message_2"},
		},
	}

	for _, test := range tests {
		dbgLogger := log.New().WithField("test", test.name)
		dbgLogger.Logger.SetLevel(log.DebugLevel)
		dbgLogger.Infof("starting test")
		cw := CloudwatchSource{}
		err = cw.ConfigureByDSN(test.dsn, map[string]string{"type": "test"}, dbgLogger)
		if err != nil && test.expectedCfgErr != "" {
			if !strings.Contains(err.Error(), test.expectedCfgErr) {
				t.Fatalf("%s expected error '%s' got error '%s'", test.name, test.expectedCfgErr, err.Error())
			}
			log.Debugf("got expected error : %s", err)
			continue
		} else if err != nil && test.expectedCfgErr == "" {
			t.Fatalf("%s unexpected error : %s", test.name, err)
			continue
		} else if test.expectedCfgErr != "" && err == nil {
			t.Fatalf("%s expected error '%s', got none", test.name, test.expectedCfgErr)
			continue
		}
		dbgLogger.Infof("config done test")
		//run pre-routine : tests use it to set group & streams etc.
		if test.pre != nil {
			test.pre(&cw)
		}
		out := make(chan types.Event)
		tmb := tomb.Tomb{}
		var rcvd_evts []types.Event

		dbgLogger.Infof("running StreamingAcquisition")
		actmb := tomb.Tomb{}
		actmb.Go(func() error {
			err := cw.OneShotAcquisition(out, &actmb)
			dbgLogger.Infof("acquis done")

			if err != nil && test.expectedStartErr != "" && !strings.Contains(err.Error(), test.expectedStartErr) {
				t.Fatalf("%s expected error '%s' got '%s'", test.name, test.expectedStartErr, err.Error())
			} else if err != nil && test.expectedStartErr == "" {
				t.Fatalf("%s unexpected error '%s'", test.name, err)
			} else if err == nil && test.expectedStartErr != "" {
				t.Fatalf("%s expected error '%s' got none", test.name, err)
			}
			return nil
		})

		//let's empty output chan
		tmb.Go(func() error {
			for {
				select {
				case in := <-out:
					log.Debugf("received event %+v", in)
					rcvd_evts = append(rcvd_evts, in)
				case <-tmb.Dying():
					log.Debugf("pumper died")
					return nil
				}
			}
		})

		if test.run != nil {
			test.run(&cw)
		} else {
			dbgLogger.Warning("no run code")
		}

		time.Sleep(5 * time.Second)
		dbgLogger.Infof("killing collector")
		tmb.Kill(nil)
		<-tmb.Dead()
		dbgLogger.Infof("killing datasource")
		actmb.Kill(nil)
		dbgLogger.Infof("waiting datasource death")
		<-actmb.Dead()
		//check results
		if test.expectedResLen != -1 {
			if test.expectedResLen != len(rcvd_evts) {
				t.Fatalf("%s : expected %d results got %d -> %v", test.name, test.expectedResLen, len(rcvd_evts), rcvd_evts)
			} else {
				dbgLogger.Debugf("got %d expected messages", len(rcvd_evts))
			}
		}
		if len(test.expectedResMessages) != 0 {
			res := test.expectedResMessages
			for idx, v := range rcvd_evts {
				if len(res) == 0 {
					t.Fatalf("result %d/%d : received '%s', didn't expect anything (recvd:%d, expected:%d)", idx, len(rcvd_evts), v.Line.Raw, len(rcvd_evts), len(test.expectedResMessages))
				}
				if res[0] != v.Line.Raw {
					t.Fatalf("result %d/%d : expected '%s', received '%s' (recvd:%d, expected:%d)", idx, len(rcvd_evts), res[0], v.Line.Raw, len(rcvd_evts), len(test.expectedResMessages))
				}
				dbgLogger.Debugf("got message '%s'", res[0])
				res = res[1:]
			}
			if len(res) != 0 {
				t.Fatalf("leftover unmatched results : %v", res)
			}

		}
		if test.post != nil {
			test.post(&cw)
		}
	}

}
