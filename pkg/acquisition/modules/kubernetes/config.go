package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	Selector       string `yaml:"selector"`
	Namespace      string `yaml:"namespace"`
	KubeConfigFile string `yaml:"kube_config,omitempty"`
	KubeContext    string `yaml:"kube_context,omitempty"`
}

func ConfigurationFromYAML(yamlConfig []byte) (Configuration, error) {
	var cfg Configuration

	if err := yaml.UnmarshalWithOptions(yamlConfig, &cfg, yaml.Strict()); err != nil {
		return cfg, fmt.Errorf("cannot parse: %s", yaml.FormatError(err, false, false))
	}

	cfg.SetDefaults()

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func (c *Configuration) SetDefaults() {
	if c.Namespace == "" {
		c.Namespace = "default"
	}

	if c.Mode == "" {
		c.Mode = configuration.TAIL_MODE
	}
	if c.KubeConfigFile == "" {
		home, _ := os.UserHomeDir()
		c.KubeConfigFile = filepath.Join(home, ".kube", "config")
	}
}

func (c *Configuration) Validate() error {
	if c.Selector == "" {
		return errors.New("selector must be set in kubernetes acquisition")
	}
	return nil
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	cfg, err := ConfigurationFromYAML(yamlConfig)
	if err != nil {
		return err
	}

	if s.logger != nil {
		s.logger.Tracef("Kubernetes configuration: %+v", cfg)
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
