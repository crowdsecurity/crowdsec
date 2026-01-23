package syslogacquisition

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func writeToSyslog(ctx context.Context, logs []string) error {
	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "udp", "127.0.0.1:4242")
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	for _, log := range logs {
		n, err := fmt.Fprint(conn, log)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}

		if n != len(log) {
			return fmt.Errorf("short write (%d/%d): %w", n, len(log), err)
		}
	}

	return nil
}

func TestStreamingAcquisition(t *testing.T) {
	ctx := t.Context()

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
			logs: []string{
				`<13>1 2021-05-18T11:58:40.828081+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla`,
				`<13>1 2021-05-18T12:12:37.560695+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla2[foobar]`,
			},
		},
		{
			name: "RFC3164",
			config: `source: syslog
listen_port: 4242
listen_addr: 127.0.0.1`,
			expectedLines: 3,
			logs: []string{
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2[foobar]`,
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2`,
				`<13>May 18 12:37:56 mantis sshd: blabla2`,
				`<13>May 18 12:37:56 mantis sshd`,
			},
		},
		{
			name: "RFC3164 - no parsing",
			config: `source: syslog
listen_port: 4242
listen_addr: 127.0.0.1
disable_rfc_parser: true`,
			expectedLines: 5,
			logs: []string{
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2[foobar]`,
				`<13>May 18 12:37:56 mantis sshd[49340]: blabla2`,
				`<13>May 18 12:37:56 mantis sshd: blabla2`,
				`<13>May 18 12:37:56 mantis sshd`,
				`<999>May 18 12:37:56 mantis sshd`,
				`<1000>May 18 12:37:56 mantis sshd`,
				`>?> asd`,
				`<asd>asdasd`,
				`<1a asd`,
				`<123123>asdasd`,
			},
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
		t.Run(ts.name, func(t *testing.T) {
			subLogger := log.WithField("type", ModuleName)
			s := Source{}

			err := s.Configure(ctx, []byte(ts.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			out := make(chan pipeline.Event)

			// if an error from Serve() is expected, run it synchronously
			if ts.expectedErr != "" {
				err = s.Stream(ctx, out)
				cstest.RequireErrorContains(t, err, ts.expectedErr)

				return
			}

			g, gctx := errgroup.WithContext(ctx)

			gctx, cancel := context.WithCancel(gctx)

			g.Go(func() error {
				return s.Stream(gctx, out)
			})

			actualLines := 0

			// wait for server to be ready
			time.Sleep(500*time.Millisecond)
			err = writeToSyslog(gctx, ts.logs)
			require.NoError(t, err)

			require.Eventually(t, func() bool {
				for {
					select {
					case <-out:
						actualLines++
					default:
						return actualLines == ts.expectedLines
					}
				}
			}, 1*time.Second, 100*time.Millisecond)

			cancel()

			err = g.Wait()
			require.NoError(t, err)
		})
	}
}
