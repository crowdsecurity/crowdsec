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
	HubDir             string            `yaml:"-"`
	DataDir            string            `yaml:"-"`
	ConfigDir          string            `yaml:"-"`
	HubIndexFile       string            `yaml:"-"`
	SimulationFilePath string            `yaml:"-"`
	PrometheusUrl      string            `yaml:"prometheus_uri"`
}

func (c *Config) LoadCSCLI() error {
	if c.Cscli == nil {
		c.Cscli = &CscliCfg{}
	}
	c.Cscli.ConfigDir = c.ConfigPaths.ConfigDir
	c.Cscli.DataDir = c.ConfigPaths.DataDir
	c.Cscli.HubDir = c.ConfigPaths.HubDir
	c.Cscli.HubIndexFile = c.ConfigPaths.HubIndexFile

	if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
		c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d/metrics", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
	}

	return nil
}
