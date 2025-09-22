package csconfig

import (
	"net"
	"strconv"
)

type CscliCfg struct {
	Output           string           `yaml:"output,omitempty"`
	Color            string           `yaml:"color,omitempty"`
	HubBranch        string           `yaml:"hub_branch"`
	HubURLTemplate   string           `yaml:"__hub_url_template__,omitempty"`
	HubWithContent   bool             `yaml:"hub_with_content,omitempty"`
	SimulationConfig SimulationConfig `yaml:"-"`
	DbConfig         *DatabaseCfg     `yaml:"-"`

	SimulationFilePath string `yaml:"-"`
	PrometheusUrl      string `yaml:"prometheus_uri"`
}

const defaultHubURLTemplate = "https://cdn-hub.crowdsec.net/crowdsecurity/%s/%s"

func (c *Config) loadCSCLI() {
	if c.Cscli == nil {
		c.Cscli = &CscliCfg{}
	}

	if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
		c.Cscli.PrometheusUrl = "http://" + net.JoinHostPort(
			c.Prometheus.ListenAddr,
			strconv.Itoa(c.Prometheus.ListenPort),
		) + "/metrics"
	}

	if c.Cscli.HubURLTemplate == "" {
		c.Cscli.HubURLTemplate = defaultHubURLTemplate
	}
}
