package kubernetespodlogs

import (
	"context"
	"fmt"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	Label     string `yaml:"label"`
	Namespace string `yaml:"namespace"`
}

func (d *Source) UnmarshalConfig(yamlConfig []byte) error {
	d.Config = Configuration{
		Label:     "",
		Namespace: "default",
	}

	if err := yaml.UnmarshalWithOptions(yamlConfig, &d.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("while parsing KubernetesAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if d.logger != nil {
		d.logger.Tracef("DockerAcquisition configuration: %+v", d.Config)
	}

	return nil
}

func (d *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	d.logger = logger
	d.metricsLevel = metricsLevel

	err := d.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}
