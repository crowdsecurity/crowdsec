package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"

	"gopkg.in/yaml.v2"
)

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "splunk-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

type PluginConfig struct {
	Name     string  `yaml:"name"`
	URL      string  `yaml:"url"`
	Token    string  `yaml:"token"`
	LogLevel *string `yaml:"log_level"`
}

type Splunk struct {
	PluginConfigByName map[string]PluginConfig
	Client             http.Client
}

type Payload struct {
	Event string `json:"event"`
}

func (s *Splunk) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return &protobufs.Empty{}, fmt.Errorf("splunk invalid config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("received notify signal for %s config", notification.Name))

	p := Payload{Event: notification.Text}
	data, err := json.Marshal(p)
	if err != nil {
		return &protobufs.Empty{}, err
	}

	req, err := http.NewRequest(http.MethodPost, cfg.URL, strings.NewReader(string(data)))
	if err != nil {
		return &protobufs.Empty{}, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Splunk %s", cfg.Token))
	logger.Debug(fmt.Sprintf("posting event %s to %s", string(data), req.URL))
	resp, err := s.Client.Do(req.WithContext(ctx))
	if err != nil {
		return &protobufs.Empty{}, err
	}

	if resp.StatusCode != http.StatusOK {
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return &protobufs.Empty{}, fmt.Errorf("got non 200 response and failed to read error %s", err)
		}
		return &protobufs.Empty{}, fmt.Errorf("got non 200 response %s", string(content))
	}
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &protobufs.Empty{}, fmt.Errorf("failed to read response body got error %s", err)
	}
	logger.Debug(fmt.Sprintf("got response %s", string(respData)))
	return &protobufs.Empty{}, nil
}

func (s *Splunk) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	s.PluginConfigByName[d.Name] = d
	logger.Debug(fmt.Sprintf("Splunk plugin '%s' use URL '%s'", d.Name, d.URL))
	return &protobufs.Empty{}, err
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	sp := &Splunk{PluginConfigByName: make(map[string]PluginConfig), Client: *client}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"splunk": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
