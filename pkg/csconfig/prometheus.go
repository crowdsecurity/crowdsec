package csconfig

import "fmt"

type PrometheusCfg struct {
	Enabled    bool   `yaml:"enabled"`
	Level      string `yaml:"level"` //aggregated|full
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
}

func (c *Config) LoadPrometheus() error {
	if c.Cscli != nil && c.Cscli.PrometheusUrl == "" && c.Prometheus != nil {
		if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
			c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
		}
	}
	return nil
}
