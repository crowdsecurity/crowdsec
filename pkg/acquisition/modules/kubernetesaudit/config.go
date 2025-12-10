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

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	k8sConfig := Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &k8sConfig, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse k8s-audit configuration: %s", yaml.FormatError(err, false, false))
	}

	s.config = k8sConfig

	if s.config.ListenAddr == "" {
		return errors.New("listen_addr cannot be empty")
	}

	if s.config.ListenPort == 0 {
		return errors.New("listen_port cannot be empty")
	}

	if s.config.WebhookPath == "" {
		return errors.New("webhook_path cannot be empty")
	}

	if s.config.WebhookPath[0] != '/' {
		s.config.WebhookPath = "/" + s.config.WebhookPath
	}

	if s.config.Mode == "" {
		s.config.Mode = configuration.TAIL_MODE
	}

	return nil
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
