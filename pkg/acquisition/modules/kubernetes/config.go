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

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{
		Selector:    "",
		Namespace:   "default",
		KubeContext: "",
	}

	if err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("while parsing KubernetesAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.logger != nil {
		s.logger.Tracef("Kubernetes configuration: %+v", s.Config)
	}

	return nil
}

func (s *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
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

func (s *Source) Validate() error {
	if s.Config.Selector == "" {
		return errors.New("selector must be set in kubernetes acquisition")
	}
	return nil
}
