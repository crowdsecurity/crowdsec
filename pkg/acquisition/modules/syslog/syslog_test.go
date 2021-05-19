package syslogacquisition

import (
	"fmt"
	"net"
	"testing"
	"time"

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
		if test.expectedErr != "" {
			if err == nil {
				t.Fatalf("Expected error but got nothing : %+v", test)
			}
			assert.Contains(t, err.Error(), test.expectedErr)
		}
	}
}

func writeToSyslog(logs []string) {
	conn, err := net.Dial("udp", "127.0.0.1:4242")
	if err != nil {
		fmt.Printf("could not establish connection to syslog server : %s", err)
		return
	}
	for _, log := range logs {
		fmt.Fprint(conn, log)
	}
}

func TestStreamingAcquisition(t *testing.T) {
	tests := []struct {
		config        string
		expectedErr   string
		logs          []string
		expectedLines int
	}{
		{
			config:      `source: syslog`,
			expectedErr: "could not start syslog server: could not listen on port 514: listen udp 127.0.0.1:514: bind: permission denied",
		},
		{
			config: `
source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			logs: []string{"foobar", "bla", "pouet"},
		},
		{
			config: `
source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			expectedLines: 2,
			logs: []string{`<13>1 2021-05-18T11:58:40.828081+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla`,
				`<13>1 2021-05-18T12:12:37.560695+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla2[foobar]`},
		},
		{
			config: `
source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			expectedLines: 3,
			logs: []string{`<13>May 18 12:37:56 mantis sshd[49340]: blabla2[foobar]`,
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2`,
				`<13>May 18 12:37:56 mantis sshd: blabla2`,
				`<13>May 18 12:37:56 mantis sshd`},
		},
	}

	for _, ts := range tests {
		subLogger := log.WithFields(log.Fields{
			"type": "syslog",
		})
		s := SyslogSource{}
		_ = s.Configure([]byte(ts.config), subLogger)
		tomb := tomb.Tomb{}
		out := make(chan types.Event)
		err := s.StreamingAcquisition(out, &tomb)
		if ts.expectedErr != "" && err == nil {
			t.Fatalf("expected error but got nothing : %+v", ts)
		} else if ts.expectedErr == "" && err != nil {
			t.Fatalf("unexpected error : %s", err)
		} else if ts.expectedErr != "" && err != nil {
			assert.Contains(t, err.Error(), ts.expectedErr)
			continue
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
	}
}
