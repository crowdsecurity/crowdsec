package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

type PluginConfig struct {
	Name       string `yaml:"name"`
	LogLevel   string `yaml:"log_level"`
	OutputFile string `yaml:"output_file"`
}

type DummyPlugin struct {
	protobufs.UnimplementedNotifierServer
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "dummy-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *DummyPlugin) Notify(_ context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	name := notification.GetName()
	cfg, ok := s.PluginConfigByName[name]

	if !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", name)
	}

	if cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("received signal for %s config", name))

	text := notification.GetText()

	logger.Debug(text)

	if cfg.OutputFile != "" {
		f, err := os.OpenFile(cfg.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			logger.Error(fmt.Sprintf("Cannot open notification file: %s", err))
		}

		if _, err := f.WriteString(text + "\n"); err != nil {
			f.Close()
			logger.Error(fmt.Sprintf("Cannot write notification to file: %s", err))
		}

		err = f.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("Cannot close notification file: %s", err))
		}
	}

	fmt.Fprintln(os.Stdout, text)

	// simulate a slow plugin in tests: hold the delivery open so the broker
	// has an in-flight call during shutdown. Empty batches (signaled by the
	// watcher on shutdown even with nothing pending) return right away.
	if d, err := time.ParseDuration(os.Getenv("DUMMY_SLEEP")); err == nil && d > 0 && text != "" && text != "null" && text != "[]" {
		time.Sleep(d)
	}

	return &protobufs.Empty{}, nil
}

func (s *DummyPlugin) Configure(_ context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.GetConfig(), &d)
	s.PluginConfigByName[d.Name] = d

	return &protobufs.Empty{}, err
}

func main() {
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &DummyPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"dummy": &csplugin.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
