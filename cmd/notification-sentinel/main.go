package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v3"
)

type PluginConfig struct {
	Name       string  `yaml:"name"`
	CustomerID string  `yaml:"customer_id"`
	SharedKey  string  `yaml:"shared_key"`
	LogType    string  `yaml:"log_type"`
	LogLevel   *string `yaml:"log_level"`
}

type SentinelPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "sentinel-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *SentinelPlugin) getAuthorizationHeader(now string, length int, pluginName string) (string, error) {
	xHeaders := "x-ms-date:" + now

	stringToHash := fmt.Sprintf("POST\n%d\napplication/json\n%s\n/api/logs", length, xHeaders)
	decodedKey, _ := base64.StdEncoding.DecodeString(s.PluginConfigByName[pluginName].SharedKey)

	h := hmac.New(sha256.New, decodedKey)
	h.Write([]byte(stringToHash))

	encodedHash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	authorization := "SharedKey " + s.PluginConfigByName[pluginName].CustomerID + ":" + encodedHash

	logger.Trace("authorization header", "header", authorization)

	return authorization, nil
}

func (s *SentinelPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {

	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info("received notification for sentinel config", "name", notification.Name)

	url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", s.PluginConfigByName[notification.Name].CustomerID)
	body := strings.NewReader(notification.Text)

	//Cannot use time.RFC1123 as azure wants GMT, not UTC
	now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")

	authorization, err := s.getAuthorizationHeader(now, len(notification.Text), notification.Name)

	if err != nil {
		return &protobufs.Empty{}, err
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		logger.Error("failed to create request", "error", err)
		return &protobufs.Empty{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", s.PluginConfigByName[notification.Name].LogType)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("x-ms-date", now)

	client := &http.Client{}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		logger.Error("failed to send request", "error", err)
		return &protobufs.Empty{}, err
	}
	defer resp.Body.Close()
	logger.Debug("sent notification to sentinel", "status", resp.Status)

	if resp.StatusCode != http.StatusOK {
		return &protobufs.Empty{}, fmt.Errorf("failed to send notification to sentinel: %s", resp.Status)
	}

	return &protobufs.Empty{}, nil
}

func (s *SentinelPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
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

	sp := &SentinelPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"sentinel": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
