package kubernetesauditacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	WebhookPath                       string `yaml:"webhook_path"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func ConfigurationFromYAML(y []byte) (Configuration, error) {
	var cfg Configuration

	if err := yaml.UnmarshalWithOptions(y, &cfg, yaml.Strict()); err != nil {
		return cfg, fmt.Errorf("cannot parse: %s", yaml.FormatError(err, false, false))
	}

	cfg.SetDefaults()
	cfg.Normalize()

	err := cfg.Validate()
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

func (c *Configuration) SetDefaults() {
	if c.Mode == "" {
		c.Mode = configuration.TAIL_MODE
	}
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	cfg, err := ConfigurationFromYAML(yamlConfig)
	if err != nil {
		return err
	}

	s.config = cfg

	return nil
}

func (c *Configuration) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen_addr cannot be empty")
	}

	if c.ListenPort == 0 {
		return errors.New("listen_port cannot be empty")
	}

	if c.WebhookPath == "" {
		return errors.New("webhook_path cannot be empty")
	}

	return nil
}


func (c *Configuration) Normalize() {
	if c.WebhookPath != "" && c.WebhookPath[0] != '/' {
		c.WebhookPath = "/" + c.WebhookPath
	}
}

func (s *Source) Configure(_ context.Context, config []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(config)
	if err != nil {
		return err
	}

	s.logger.Tracef("K8SAudit configuration: %+v", s.config)

	s.addr = fmt.Sprintf("%s:%d", s.config.ListenAddr, s.config.ListenPort)

	s.mux = http.NewServeMux()

	s.server = &http.Server{
		Addr:      s.addr,
		Handler:   s.mux,
		Protocols: &http.Protocols{},
	}

	s.server.Protocols.SetHTTP1(true)
	s.server.Protocols.SetUnencryptedHTTP2(true)
	s.server.Protocols.SetHTTP2(true)

	s.mux.HandleFunc(s.config.WebhookPath, s.webhookHandler)

	return nil
}
