package kubernetespodlogs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	Selector       string `yaml:"selector"`
	Namespace      string `yaml:"namespace"`
	Auth           *Auth  `yaml:"auth,omitempty"`
	KubeConfigFile string `yaml:"kube_config,omitempty"`
}

type Auth struct {
	Cluster api.Cluster  `yaml:"cluster,omitempty"`
	User    api.AuthInfo `yaml:"user,omitempty"`
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.Config = Configuration{
		Selector:  "",
		Namespace: "default",
	}

	if err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("while parsing KubernetesAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.logger != nil {
		s.logger.Tracef("DockerAcquisition configuration: %+v", s.Config)
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
	if c.Auth == nil && c.KubeConfigFile == "" {
		home, _ := os.UserHomeDir()
		c.KubeConfigFile = filepath.Join(home, ".kube", "config")
	}
}

func (s *Source) Validate() error {
	if s.Config.Selector == "" {
		return fmt.Errorf("label must be set in kubernetespodlogs acquisition")
	}
	if s.Config.Auth != nil && s.Config.KubeConfigFile != "" {
		return fmt.Errorf("cannot use both auth and kube_config options")

	}
	return nil
}
