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

func validatePort(port int) bool {
	return port > 0 && port <= 65535
}

func validateAddr(addr string) bool {
	return net.ParseIP(addr) != nil
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.config = Configuration{}
	s.config.Mode = configuration.TAIL_MODE

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse syslog configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.config.Addr == "" {
		s.config.Addr = "127.0.0.1" // do we want a usable or secure default ?
	}

	if s.config.Port == 0 {
		s.config.Port = 514
	}

	if s.config.MaxMessageLen == 0 {
		s.config.MaxMessageLen = 2048
	}

	if !validatePort(s.config.Port) {
		return fmt.Errorf("invalid port %d", s.config.Port)
	}

	if !validateAddr(s.config.Addr) {
		return fmt.Errorf("invalid listen IP %s", s.config.Addr)
	}

	return nil
}

func (s *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}
