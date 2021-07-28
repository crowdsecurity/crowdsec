package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"os"

	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name                string            `yaml:"name"`
	Endpoint            string            `yaml:"endpoint"`
	Headers             map[string]string `yaml:"headers"`
	SkipTLSVerification bool              `yaml:"skip_tls_verification"`
	Method              string            `yaml:"method"`
}

type HTTPPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

func (s *HTTPPlugin) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	log.Info("received signal")
	pluginConfig := s.PluginConfigByName[notification.Name]
	client := http.Client{}

	if pluginConfig.SkipTLSVerification {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	request, err := http.NewRequest(pluginConfig.Method, pluginConfig.Endpoint, bytes.NewReader([]byte(notification.Text)))
	if err != nil {
		return nil, err
	}

	for headerName, headerValue := range pluginConfig.Headers {
		request.Header.Add(headerName, headerValue)
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, err
	}

	return &Empty{}, nil
}

func (s *HTTPPlugin) Configure(ctx context.Context, config *Config) (*Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	s.PluginConfigByName[d.Name] = d
	return &Empty{}, err
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
			"http": &NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
