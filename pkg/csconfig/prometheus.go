package csconfig

import (
	"errors"
	"fmt"
	"strings"
)

/**/
type PrometheusCfg struct {
	Enabled    bool   `yaml:"enabled"`
	Level      string `yaml:"level"` //aggregated|full
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
	ListenURI  string `yaml:"listen_uri"`
}

func (c *Config) LoadPrometheus() error {
	if c.Cscli != nil && c.Cscli.PrometheusUrl == "" && c.Prometheus != nil {
		if (c.Prometheus.ListenAddr != "" || c.Prometheus.ListenPort != 0) && c.Prometheus.ListenURI != "" {
			return errors.New("'listen_addr' or 'listen_port' and 'listen_uri' are not supported at the same time")
		}
		if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
			c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
		}
		if c.Prometheus.ListenURI != "" {
			if !strings.HasPrefix(c.Prometheus.ListenURI, "http://") {
				return errors.New("no other protocol supported than http")
			}
			c.Cscli.PrometheusUrl = c.Prometheus.ListenURI
		}
	}

	return nil
}
