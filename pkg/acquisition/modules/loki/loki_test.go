package loki

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
)

func TestConfiguration(t *testing.T) {

	log.Infof("Test 'TestConfigure'")

	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd`,
			expectedErr: "line 1: field foobar not found in type loki.LokiConfiguration",
		},
		{
			config: `
mode: tail
source: loki`,
			expectedErr: "Cannot build Loki url",
		},
		{
			config: `
mode: tail
source: loki
url: stuff://localhost:3100
`,
			expectedErr: "unknown scheme : stuff",
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
`,
			expectedErr: "",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "loki",
	})
	for _, test := range tests {
		f := LokiSource{}
		err := f.Configure([]byte(test.config), subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestConfigureDSN(t *testing.T) {
	// TODO
}

func TestStreamingAcquisition(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.Info("Test 'TestStreamingAcquisition'")
	tests := []struct {
		config         string
		expectedErr    string
		streamErr      string
		expectedOutput string
		expectedLines  int
		logType        string
		logLevel       log.Level
	}{
		{
			config: `
mode: tail
source: loki
url: http://127.0.0.1:3101
`, // No Loki server here
			expectedErr:    "",
			streamErr:      `Get "http://127.0.0.1:3101/ready": dial tcp 127.0.0.1:3101: connect: connection refused`,
			expectedOutput: "",
			expectedLines:  0,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
		{
			config: `
mode: tail
source: loki
url: http://127.0.0.1:3100
query: >
        {server="demo"}
`, // No Loki server here
			expectedErr:    "",
			streamErr:      "",
			expectedOutput: "",
			expectedLines:  0,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
	}
	for _, ts := range tests {
		var logger *log.Logger
		var subLogger *log.Entry
		if ts.expectedOutput != "" {
			logger.SetLevel(ts.logLevel)
			subLogger = logger.WithFields(log.Fields{
				"type": "loki",
			})
		} else {
			subLogger = log.WithFields(log.Fields{
				"type": "loki",
			})
		}
		out := make(chan types.Event)
		lokiTomb := tomb.Tomb{}
		lokiSource := LokiSource{}
		err := lokiSource.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		streamTomb := tomb.Tomb{}
		streamTomb.Go(func() error {
			return lokiSource.StreamingAcquisition(out, &lokiTomb)
		})

		readTomb := tomb.Tomb{}
		readTomb.Go(func() error {
			for i := 0; i < 20; i++ {
				evt := <-out
				fmt.Println(evt)
			}
			return nil
		})

		writerTomb := tomb.Tomb{}
		writerTomb.Go(func() error {
			streams := LogStreams{
				Streams: []LogStream{
					{
						Stream: map[string]string{
							"server": "demo",
							"domain": "cw.example.com",
						},
						Values: make([]LogValue, 20),
					},
				},
			}
			for i := 0; i < 20; i++ {
				streams.Streams[0].Values[i] = LogValue{
					Time: time.Now(),
					Line: fmt.Sprintf("Log line #%d", i),
				}
			}
			buff, err := json.Marshal(streams)
			if err != nil {
				return err
			}
			resp, err := http.Post("http://127.0.0.1:3100/loki/api/v1/push", "application/json", bytes.NewBuffer(buff))
			if err != nil {
				return err
			}
			if resp.StatusCode != 204 {
				b, _ := ioutil.ReadAll(resp.Body)
				log.Error(string(b))
				return fmt.Errorf("Bad post status %d", resp.StatusCode)
			}
			subLogger.Info("20 Events sent")
			return nil
		})
		err = writerTomb.Wait()
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		err = streamTomb.Wait()
		cstest.AssertErrorContains(t, err, ts.streamErr)

		if err == nil {
			err = readTomb.Wait()
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}
		}
	}
}

type LogStreams struct {
	Streams []LogStream `json:"streams"`
}

type LogStream struct {
	Stream map[string]string `json:"stream"`
	Values []LogValue        `json:"values"`
}

type LogValue struct {
	Time time.Time
	Line string
}

func (l *LogValue) MarshalJSON() ([]byte, error) {
	line, err := json.Marshal(l.Line)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`[%d,%s]`, l.Time.UnixNano(), string(line))), nil
}
