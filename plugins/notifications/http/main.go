package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
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
}

type HTTPPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "http-plugin",
	Level:      hclog.LevelFromString("DEBUG"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *HTTPPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]
	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	} else {
		logger.SetLevel(hclog.Info)
	}

	logger.Info(fmt.Sprintf("received signal for %s config", notification.Name))
	client := http.Client{}

	if cfg.SkipTLSVerification {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	request, err := http.NewRequest(cfg.Method, cfg.URL, bytes.NewReader([]byte(notification.Text)))
	if err != nil {
		return nil, err
	}

	for headerName, headerValue := range cfg.Headers {
		logger.Debug(fmt.Sprintf("adding header %s: %s", headerName, headerValue))
		request.Header.Add(headerName, headerValue)
	}
	logger.Debug(fmt.Sprintf("making HTTP %s call to %s with body %s", cfg.Method, cfg.URL, string(notification.Text)))
	resp, err := client.Do(request)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to make HTTP request : %s", err))
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body got error %s", string(err.Error()))
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
	s.PluginConfigByName[d.Name] = d
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
