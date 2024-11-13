package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/slack-go/slack"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

type PluginConfig struct {
	Name      string  `yaml:"name"`
	Webhook   string  `yaml:"webhook"`
	Channel   string  `yaml:"channel"`
	Username  string  `yaml:"username"`
	IconEmoji string  `yaml:"icon_emoji"`
	IconURL   string  `yaml:"icon_url"`
	LogLevel  *string `yaml:"log_level"`
}
type Notify struct {
	protobufs.UnimplementedNotifierServer
	ConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "slack-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (n *Notify) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := n.ConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}

	cfg := n.ConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Info(fmt.Sprintf("found notify signal for %s config", notification.Name))
	logger.Debug(fmt.Sprintf("posting to %s webhook, message %s", cfg.Webhook, notification.Text))

	err := slack.PostWebhookContext(ctx, cfg.Webhook, &slack.WebhookMessage{
		Text:      notification.Text,
		Channel:   cfg.Channel,
		Username:  cfg.Username,
		IconEmoji: cfg.IconEmoji,
		IconURL:   cfg.IconURL,
	})
	if err != nil {
		logger.Error(err.Error())
	}

	return &protobufs.Empty{}, err
}

func (n *Notify) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}

	if err := yaml.Unmarshal(config.Config, &d); err != nil {
		return nil, err
	}

	n.ConfigByName[d.Name] = d
	logger.Debug(fmt.Sprintf("Slack plugin '%s' use URL '%s'", d.Name, d.Webhook))

	return &protobufs.Empty{}, nil
}

func main() {
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"slack": &csplugin.NotifierPlugin{
				Impl: &Notify{ConfigByName: make(map[string]PluginConfig)},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
