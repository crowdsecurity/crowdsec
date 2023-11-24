package csconfig

import (
	"fmt"
)

/*cscli specific config, such as hub directory*/
type CscliCfg struct {
	Output             string            `yaml:"output,omitempty"`
	Color              string            `yaml:"color,omitempty"`
	HubBranch          string            `yaml:"hub_branch"`
	SimulationConfig   *SimulationConfig `yaml:"-"`
	DbConfig           *DatabaseCfg      `yaml:"-"`

	SimulationFilePath string            `yaml:"-"`
	PrometheusUrl      string            `yaml:"prometheus_uri"`
}

func (c *Config) loadCSCLI() error {
	if c.Cscli == nil {
		c.Cscli = &CscliCfg{}
	}

	if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
		c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d/metrics", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
	}

	return nil
}
