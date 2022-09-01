package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name       string  `yaml:"name"`
	LogLevel   *string `yaml:"log_level"`
	OutputFile *string `yaml:"output_file"`
	API_Key    string  `yaml:"api_key"`
}

type AbuseipdbPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "abuseipdb-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *AbuseipdbPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("received signal for %s config", notification.Name))

	alerts := []models.Alert{}
	err := json.Unmarshal([]byte(notification.Text), &alerts)
	if err != nil {
		logger.Error(err.Error())
	}

	for _, alert := range alerts {
		report := Report{}.New(&alert)

		client := http.Client{}

		params := url.Values{}
		params.Add("ip", report.Ip)
		params.Add("categories", report.Categories)
		params.Add("comment", report.Comment)

		request, err := http.NewRequest("POST", "https://api.abuseipdb.com/api/v2/report", strings.NewReader(params.Encode()))
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to make New Request: %s", err))
			return nil, err
		}

		request.Header.Set("Key", cfg.API_Key)
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := client.Do(request)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to make HTTP request : %s", err))
			return nil, err
		}

		defer response.Body.Close()

		bodyText, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body got error %s", err)
		}
		logger.Info(string(bodyText))
	}

	return &protobufs.Empty{}, nil
}

func (s *AbuseipdbPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
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

	sp := &AbuseipdbPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"abuseipdb": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
