package httpacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	// IPFilter                       []string          `yaml:"ip_filter"`
	// ChunkSize                      *int64            `yaml:"chunk_size"`
	ListenAddr                        string            `yaml:"listen_addr"`
	ListenSocket                      string            `yaml:"listen_socket"`
	Path                              string            `yaml:"path"`
	AuthType                          string            `yaml:"auth_type"`
	BasicAuth                         *BasicAuthConfig  `yaml:"basic_auth"`
	Headers                           map[string]string `yaml:"headers"`
	TLS                               *TLSConfig        `yaml:"tls"`
	CustomStatusCode                  *int              `yaml:"custom_status_code"`
	CustomHeaders                     map[string]string `yaml:"custom_headers"`
	MaxBodySize                       *int64            `yaml:"max_body_size"`
	Timeout                           *time.Duration    `yaml:"timeout"`
	configuration.DataSourceCommonCfg                   `yaml:",inline"`
}

func ConfigurationFromYAML(y []byte) (Configuration, error) {
	var cfg Configuration

	if err := yaml.UnmarshalWithOptions(y, &cfg, yaml.Strict()); err != nil {
		return cfg, fmt.Errorf("cannot parse: %s", yaml.FormatError(err, false, false))
	}

	cfg.SetDefaults()

	err := cfg.Validate()
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ServerCert         string `yaml:"server_cert"`
	ServerKey          string `yaml:"server_key"`
	CaCert             string `yaml:"ca_cert"`
}

func (c *Configuration) SetDefaults() {
	if c.Mode == "" {
		c.Mode = configuration.TAIL_MODE
	}

	if c.Path == "" {
		c.Path = "/"
	}
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	cfg, err := ConfigurationFromYAML(yamlConfig)
	if err != nil {
		return err
	}

	s.Config = cfg

	return nil
}

func (c *Configuration) Validate() error {
	if c.ListenAddr == "" && c.ListenSocket == "" {
		return errors.New("listen_addr or listen_socket is required")
	}

	if c.Path[0] != '/' {
		return errors.New("path must start with /")
	}

	switch c.AuthType {
	case "basic_auth":
		baseErr := "basic_auth is selected, but"
		if c.BasicAuth == nil {
			return errors.New(baseErr + " basic_auth is not provided")
		}

		if c.BasicAuth.Username == "" {
			return errors.New(baseErr + " username is not provided")
		}

		if c.BasicAuth.Password == "" {
			return errors.New(baseErr + " password is not provided")
		}
	case "headers":
		if c.Headers == nil {
			return errors.New("headers is selected, but headers is not provided")
		}
	case "mtls":
		if c.TLS == nil || c.TLS.CaCert == "" {
			return errors.New("mtls is selected, but ca_cert is not provided")
		}
	default:
		return errors.New("invalid auth_type: must be one of basic_auth, headers, mtls")
	}

	if c.TLS != nil {
		if c.TLS.ServerCert == "" {
			return errors.New("server_cert is required")
		}

		if c.TLS.ServerKey == "" {
			return errors.New("server_key is required")
		}
	}

	if c.MaxBodySize != nil && *c.MaxBodySize <= 0 {
		return errors.New("max_body_size must be positive")
	}

	/*
		if hc.ChunkSize != nil && *hc.ChunkSize <= 0 {
			return errors.New("chunk_size must be positive")
		}
	*/

	if c.CustomStatusCode != nil {
		statusText := http.StatusText(*c.CustomStatusCode)
		if statusText == "" {
			return errors.New("invalid HTTP status code")
		}
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

func (c *Configuration) NewTLSConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: c.TLS.InsecureSkipVerify,
	}

	if c.TLS.ServerCert != "" && c.TLS.ServerKey != "" {
		cert, err := tls.LoadX509KeyPair(c.TLS.ServerCert, c.TLS.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load server cert/key: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if c.AuthType == "mtls" && c.TLS.CaCert != "" {
		caCert, err := os.ReadFile(c.TLS.CaCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca cert: %w", err)
		}

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system cert pool: %w", err)
		}

		if caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &tlsConfig, nil
}
