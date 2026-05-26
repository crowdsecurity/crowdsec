package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestSetDefaults(t *testing.T) {
	t.Run("namespace defaults to 'default'", func(t *testing.T) {
		c := Configuration{}
		c.SetDefaults()
		assert.Equal(t, "default", c.Namespace)
	})

	t.Run("namespace is preserved when set", func(t *testing.T) {
		c := Configuration{DataSourceCommonCfg: configuration.DataSourceCommonCfg{}}
		c.Namespace = "kube-system"
		c.SetDefaults()
		assert.Equal(t, "kube-system", c.Namespace)
	})

	t.Run("mode defaults to tail", func(t *testing.T) {
		c := Configuration{}
		c.SetDefaults()
		assert.Equal(t, configuration.TAIL_MODE, c.Mode)
	})

	t.Run("mode is preserved when set", func(t *testing.T) {
		c := Configuration{}
		c.Mode = configuration.TAIL_MODE
		c.SetDefaults()
		assert.Equal(t, configuration.TAIL_MODE, c.Mode)
	})

	t.Run("kube_config defaults to ~/.kube/config when HOME is set", func(t *testing.T) {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home directory available")
		}
		c := Configuration{}
		c.SetDefaults()
		assert.Equal(t, filepath.Join(home, ".kube", "config"), c.KubeConfigFile)
	})

	t.Run("kube_config is preserved when set", func(t *testing.T) {
		c := Configuration{}
		c.KubeConfigFile = "/custom/kube/config"
		c.SetDefaults()
		assert.Equal(t, "/custom/kube/config", c.KubeConfigFile)
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Configuration
		expectedErr string
	}{
		{
			name:        "missing selector",
			cfg:         Configuration{DataSourceCommonCfg: configuration.DataSourceCommonCfg{Mode: configuration.TAIL_MODE}},
			expectedErr: "selector must be set",
		},
		{
			name: "unsupported mode",
			cfg: Configuration{
				DataSourceCommonCfg: configuration.DataSourceCommonCfg{Mode: configuration.CAT_MODE},
				Selector:            "app=nginx",
			},
			expectedErr: "unsupported mode",
		},
		{
			name: "valid config",
			cfg: Configuration{
				DataSourceCommonCfg: configuration.DataSourceCommonCfg{Mode: configuration.TAIL_MODE},
				Selector:            "app=nginx",
			},
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			cstest.AssertErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestConfigure(t *testing.T) {
	logger := log.WithField("type", ModuleName)

	tests := []struct {
		name        string
		yaml        string
		expectedErr string
	}{
		{
			name:        "invalid YAML",
			yaml:        "}{not yaml",
			expectedErr: "cannot parse",
		},
		{
			name:        "unknown field",
			yaml:        "source: kubernetes\nselector: app=nginx\nunknown_field: true\n",
			expectedErr: "cannot parse",
		},
		{
			name:        "missing selector",
			yaml:        "source: kubernetes\n",
			expectedErr: "selector must be set",
		},
		{
			name:        "unsupported mode",
			yaml:        "source: kubernetes\nselector: app=nginx\nmode: cat\n",
			expectedErr: "unsupported mode",
		},
		{
			name:        "valid minimal config",
			yaml:        "source: kubernetes\nselector: app=nginx\n",
			expectedErr: "",
		},
		{
			name:        "valid config with namespace",
			yaml:        "source: kubernetes\nselector: app=nginx\nnamespace: production\n",
			expectedErr: "",
		},
		{
			name:        "valid config with kube_config",
			yaml:        "source: kubernetes\nselector: app=nginx\nkube_config: /path/to/kubeconfig\n",
			expectedErr: "",
		},
		{
			name:        "valid config with kube_context",
			yaml:        "source: kubernetes\nselector: app=nginx\nkube_context: my-context\n",
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Source{}
			err := s.Configure(t.Context(), []byte(tc.yaml), logger, metrics.AcquisitionMetricsLevelNone)
			cstest.AssertErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr == "" {
				require.NotNil(t, s.logger)
				assert.Equal(t, configuration.TAIL_MODE, s.config.Mode)
			}
		})
	}
}
