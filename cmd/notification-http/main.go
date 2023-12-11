package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name                string            `yaml:"name"`
	URL                 string            `yaml:"url"`
	Headers             map[string]string `yaml:"headers"`
	SkipTLSVerification bool              `yaml:"skip_tls_verification"`
	Method              string            `yaml:"method"`
	LogLevel            *string           `yaml:"log_level"`
	Client              *http.Client      `yaml:"-"`
	CertPath            string            `yaml:"cert_path"`
	KeyPath             string            `yaml:"key_path"`
	CAPath              string            `yaml:"ca_cert_path"`
}

type HTTPPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "http-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func getCertPool(caPath string) (*x509.CertPool, error) {
	cp, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system CA certificates: %w", err)
	}

	if cp == nil {
		cp = x509.NewCertPool()
	}

	if caPath == "" {
		return cp, nil
	}

	logger.Info(fmt.Sprintf("Using CA cert '%s'", caPath))

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA certificate '%s': %w", caPath, err)
	}

	cp.AppendCertsFromPEM(caCert)

	return cp, nil
}

func getTLSClient(tlsVerify bool, caPath, certPath, keyPath string) (*http.Client, error) {
	var client *http.Client

	caCertPool, err := getCertPool(caPath)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: tlsVerify,
	}

	if certPath != "" && keyPath != "" {
		logger.Info(fmt.Sprintf("Using client certificate '%s' and key '%s'", certPath, keyPath))

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load client certificate '%s' and key '%s': %w", certPath, keyPath, err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client, err
}

func (s *HTTPPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("received signal for %s config", notification.Name))

	request, err := http.NewRequest(cfg.Method, cfg.URL, bytes.NewReader([]byte(notification.Text)))
	if err != nil {
		return nil, err
	}
	for headerName, headerValue := range cfg.Headers {
		logger.Debug(fmt.Sprintf("adding header %s: %s", headerName, headerValue))
		request.Header.Add(headerName, headerValue)
	}
	logger.Debug(fmt.Sprintf("making HTTP %s call to %s with body %s", cfg.Method, cfg.URL, notification.Text))
	resp, err := cfg.Client.Do(request.WithContext(ctx))
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to make HTTP request : %s", err))
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body got error %s", err)
	}

	logger.Debug(fmt.Sprintf("got response %s", string(respData)))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warn(fmt.Sprintf("HTTP server returned non 200 status code: %d", resp.StatusCode))
		return &protobufs.Empty{}, nil
	}

	return &protobufs.Empty{}, nil
}

func (s *HTTPPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	if err != nil {
		return nil, err
	}
	d.Client, err = getTLSClient(d.SkipTLSVerification, d.CAPath, d.CertPath, d.KeyPath)
	if err != nil {
		return nil, err
	}
	s.PluginConfigByName[d.Name] = d
	logger.Debug(fmt.Sprintf("HTTP plugin '%s' use URL '%s'", d.Name, d.URL))
	return &protobufs.Empty{}, err
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &HTTPPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"http": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
