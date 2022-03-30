package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name       string  `yaml:"name"`
	LogLevel   *string `yaml:"log_level"`
	OutputFile *string `yaml:"output_file"`
}

type DummyPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "dummy-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *DummyPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("received signal for %s config", notification.Name))
	logger.Debug(notification.Text)

	if cfg.OutputFile != nil && *cfg.OutputFile != "" {
		f, err := os.OpenFile(*cfg.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error(fmt.Sprintf("Cannot open notification file: %s", err))
		}
		if _, err := f.WriteString(notification.Text + "\n"); err != nil {
			f.Close()
			logger.Error(fmt.Sprintf("Cannot write notification to file: %s", err))
		}
		err = f.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("Cannot close notification file: %s", err))
		}
	}
	fmt.Println(notification.Text)

	return &protobufs.Empty{}, nil
}

func (s *DummyPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
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

	sp := &DummyPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"dummy": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
