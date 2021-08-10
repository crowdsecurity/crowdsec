package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"

	"github.com/slack-go/slack"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name    string `yaml:"name"`
	Webhook string `yaml:"webhook"`
}
type Notify struct {
	WebhooksByConfigName map[string]string
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "slack-plugin",
	Level:      hclog.LevelFromString("DEBUG"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (n *Notify) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	logger.Info(fmt.Sprintf("found notify signal for %s config", notification.Name))
	err := slack.PostWebhook(n.WebhooksByConfigName[notification.Name], &slack.WebhookMessage{
		Text: notification.Text,
	})
	if err != nil {
		logger.Error(err.Error())
	}

	return &Empty{}, err
}

func (n *Notify) Configure(ctx context.Context, config *Config) (*Empty, error) {
	d := PluginConfig{}
	if err := yaml.Unmarshal(config.Config, &d); err != nil {
		return nil, err
	}
	n.WebhooksByConfigName[d.Name] = d.Webhook
	return &Empty{}, nil
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"slack": &NotifierPlugin{
				Impl: &Notify{WebhooksByConfigName: make(map[string]string)},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
