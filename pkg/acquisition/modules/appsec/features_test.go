package appsecacquisition

import (
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestFeatures(t *testing.T) {
	tests := []struct {
		name         string
		appsecConfig string
		want         []string
	}{
		{
			name:         "waf only",
			appsecConfig: "name: test\n",
			want:         []string{metrics.FeatureWAF},
		},
		{
			name: "challenge hook enables bot detection",
			appsecConfig: `name: test
on_challenge:
  - apply:
      - SendChallenge()
`,
			want: []string{metrics.FeatureWAF, metrics.FeatureBotDetection},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "appsec-config.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte(tc.appsecConfig), 0o600))

			w := &Source{}
			w.SetHub(&cwhub.Hub{})
			w.SetClientConfig(&csconfig.LocalApiClientCfg{
				Credentials: &csconfig.ApiCredentialsCfg{URL: "http://127.0.0.1:8080/"},
			})

			yamlConfig := "source: appsec\nlisten_addr: 127.0.0.1:0\nappsec_config_path: " + configPath + "\n"
			require.NoError(t, w.Configure(t.Context(), []byte(yamlConfig), log.NewEntry(log.StandardLogger()), metrics.AcquisitionMetricsLevelNone))

			require.Equal(t, tc.want, w.Features())
		})
	}
}
