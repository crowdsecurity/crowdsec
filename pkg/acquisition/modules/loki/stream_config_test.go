package loki_test

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestPollingWindowConfig(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		invalid      bool
	}{
		{"defaults", "source: loki\nquery: test", false},
		{"explicit", "source: loki\nquery: test\nquery_delay: 30s\npoll_interval: 5s", false},
		{"negative delay", "source: loki\nquery: test\nquery_delay: -1s", true},
		{"negative interval", "source: loki\nquery: test\npoll_interval: -1s", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loki.Source{}
			err := s.Configure(t.Context(), []byte(tc.config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.name == "defaults" {
				require.Equal(t, 5*time.Second, s.Config.QueryDelay)
				require.Equal(t, time.Second, s.Config.PollInterval)
			} else {
				require.Equal(t, 30*time.Second, s.Config.QueryDelay)
				require.Equal(t, 5*time.Second, s.Config.PollInterval)
			}
		})
	}
}
