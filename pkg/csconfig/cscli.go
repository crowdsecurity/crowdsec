package csconfig

import (
	"fmt"
)

/*cscli specific config, such as hub directory*/
type CscliCfg struct {
	Output           string            `yaml:"output,omitempty"`
	Color            string            `yaml:"color,omitempty"`
	HubBranch        string            `yaml:"hub_branch"`
	HubURLTemplate   string            `yaml:"__hub_url_template__,omitempty"`
	HubWithContent   bool              `yaml:"hub_with_content,omitempty"`
	SimulationConfig *SimulationConfig `yaml:"-"`
	DbConfig         *DatabaseCfg      `yaml:"-"`

	SimulationFilePath string `yaml:"-"`
	PrometheusUrl      string `yaml:"prometheus_uri"`
}

const defaultHubURLTemplate = "https://cdn-hub.crowdsec.net/crowdsecurity/%s/%s"

func (c *Config) loadCSCLI() error {
	if c.Cscli == nil {
		c.Cscli = &CscliCfg{}
	}

	if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
		c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d/metrics", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
	}

	if c.Cscli.HubURLTemplate == "" {
		c.Cscli.HubURLTemplate = defaultHubURLTemplate
	}

	return nil
}
