package main

import (
	"context"
	"os"

	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"
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

func (n *Notify) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	log.Infof("found notify signal for %s config", notification.Name)
	slack.PostWebhook(n.WebhooksByConfigName[notification.Name], &slack.WebhookMessage{
		Text: notification.Text,
	})
	return &Empty{}, nil
}

func (n *Notify) Configure(ctx context.Context, config *Config) (*Empty, error) {
	d := PluginConfig{}
	if err := yaml.Unmarshal(config.Config, &d); err != nil {
		log.Error(err)
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
	})
}
