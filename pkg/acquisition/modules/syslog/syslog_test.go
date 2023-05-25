package syslogacquisition

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/stretchr/testify/assert"
)

func TestConfigure(t *testing.T) {
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config: `
foobar: bla
source: syslog`,
			expectedErr: "line 2: field foobar not found in type syslogacquisition.SyslogConfiguration",
		},
		{
			config:      `source: syslog`,
			expectedErr: "",
		},
		{
			config: `
source: syslog
listen_port: asd`,
			expectedErr: "cannot unmarshal !!str `asd` into int",
		},
		{
			config: `
source: syslog
listen_port: 424242`,
			expectedErr: "invalid port 424242",
		},
		{
			config: `
source: syslog
listen_addr: 10.0.0`,
			expectedErr: "invalid listen IP 10.0.0",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "syslog",
	})
	for _, test := range tests {
		s := SyslogSource{}
		err := s.Configure([]byte(test.config), subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func writeToSyslog(logs []string) {
	conn, err := net.Dial("udp", "127.0.0.1:4242")
	if err != nil {
		fmt.Printf("could not establish connection to syslog server : %s", err)
		return
	}
	for _, log := range logs {
		n, err := fmt.Fprint(conn, log)
		if err != nil {
			fmt.Printf("could not write to syslog server : %s", err)
			return
		}
		if n != len(log) {
			fmt.Printf("could not write to syslog server : %s", err)
			return
		}
	}
}

func TestStreamingAcquisition(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedErr   string
		logs          []string
		expectedLines int
	}{
		{
			name: "invalid msgs",
			config: `source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			logs: []string{"foobar", "bla", "pouet"},
		},
		{
			name: "RFC5424",
			config: `source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			expectedLines: 2,
			logs: []string{`<13>1 2021-05-18T11:58:40.828081+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla`,
				`<13>1 2021-05-18T12:12:37.560695+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla2[foobar]`},
		},
		{
			name: "RFC3164",
			config: `source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			expectedLines: 3,
			logs: []string{`<13>May 18 12:37:56 mantis sshd[49340]: blabla2[foobar]`,
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2`,
				`<13>May 18 12:37:56 mantis sshd: blabla2`,
				`<13>May 18 12:37:56 mantis sshd`},
		},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name          string
			config        string
			expectedErr   string
			logs          []string
			expectedLines int
		}{
			name:        "privileged port",
			config:      `source: syslog`,
			expectedErr: "could not start syslog server: could not listen on port 514: listen udp 127.0.0.1:514: bind: permission denied",
		})
	}

	for _, ts := range tests {
		ts := ts
		t.Run(ts.name, func(t *testing.T) {
			subLogger := log.WithFields(log.Fields{
				"type": "syslog",
			})
			s := SyslogSource{}
			err := s.Configure([]byte(ts.config), subLogger)
			if err != nil {
				t.Fatalf("could not configure syslog source : %s", err)
			}
			tomb := tomb.Tomb{}
			out := make(chan types.Event)
			err = s.StreamingAcquisition(out, &tomb)
			cstest.AssertErrorContains(t, err, ts.expectedErr)
			if ts.expectedErr != "" {
				return
			}
			if err != nil && ts.expectedErr == "" {
				t.Fatalf("unexpected error while starting syslog server: %s", err)
				return
			}

			actualLines := 0
			go writeToSyslog(ts.logs)
		READLOOP:
			for {
				select {
				case <-out:
					actualLines++
				case <-time.After(2 * time.Second):
					break READLOOP
				}
			}
			assert.Equal(t, ts.expectedLines, actualLines)
			tomb.Kill(nil)
			tomb.Wait()
		})
	}
}
