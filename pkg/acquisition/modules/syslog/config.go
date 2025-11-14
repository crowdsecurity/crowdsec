package syslogacquisition

import (
	"context"
	"fmt"
	"net"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	Proto                             string `yaml:"protocol,omitempty"`
	Port                              int    `yaml:"listen_port,omitempty"`
	Addr                              string `yaml:"listen_addr,omitempty"`
	MaxMessageLen                     int    `yaml:"max_message_len,omitempty"`
	DisableRFCParser                  bool   `yaml:"disable_rfc_parser,omitempty"` // if true, we don't try to be smart and just remove the PRI
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func ConfigurationFromYAML(y []byte) (Configuration, error) {
	var cfg Configuration

	if err := yaml.UnmarshalWithOptions(y, &cfg, yaml.Strict()); err != nil {
		return cfg, fmt.Errorf("cannot parse: %s", yaml.FormatError(err, false, false))
	}

	cfg.SetDefaults()

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func (c *Configuration) SetDefaults() {
	if c.Mode == "" {
		c.Mode = configuration.TAIL_MODE
	}

	if c.Addr == "" {
		c.Addr = "127.0.0.1" // do we want a usable or secure default ?
	}

	if c.Port == 0 {
		c.Port = 514
	}

	if c.MaxMessageLen == 0 {
		c.MaxMessageLen = 2048
	}
}

func (c *Configuration) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}

	if net.ParseIP(c.Addr) == nil {
		return fmt.Errorf("invalid listen IP %s", c.Addr)
	}

	return nil
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	cfg, err := ConfigurationFromYAML(yamlConfig)
	if err != nil {
		return err
	}

	s.config = cfg

	return nil
}

func (s *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.logger = logger
	s.metricsLevel = metricsLevel

	return nil
}
