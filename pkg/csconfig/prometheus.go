package csconfig

import "github.com/crowdsecurity/crowdsec/pkg/metrics"

type PrometheusCfg struct {
	Enabled    bool                       `yaml:"enabled"`
	Level      metrics.MetricsLevelConfig `yaml:"level"`
	ListenAddr string                     `yaml:"listen_addr"`
	ListenPort int                        `yaml:"listen_port"`
}
