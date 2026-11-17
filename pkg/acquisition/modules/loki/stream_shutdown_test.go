package loki_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type shutdownTransport func(*http.Request) (*http.Response, error)

func (f shutdownTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStreamingShutdownPreservesReaderErrors(t *testing.T) {
	for _, mode := range []string{"context", "tomb", "reader error"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				original := http.DefaultClient
				http.DefaultClient = &http.Client{Transport: shutdownTransport(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header)}, nil
				})}
				t.Cleanup(func() { http.DefaultClient = original })
				source := loki.Source{}
				config := []byte("source: loki\nurl: http://loki\nquery: test\nno_ready_check: true\nquery_delay: 1s\npoll_interval: 1s\nmax_failure_duration: 3s")
				require.NoError(t, source.Configure(t.Context(), config, log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				life := &tomb.Tomb{}
				require.NoError(t, source.StreamingAcquisition(ctx, make(chan pipeline.Event), life))
				if mode != "reader error" {
					synctest.Wait()
					if mode == "context" {
						cancel()
					} else {
						life.Kill(nil)
					}
					require.NoError(t, life.Wait())
				} else {
					require.ErrorContains(t, life.Wait(), "HTTP 503")
				}
			})
		})
	}
}
