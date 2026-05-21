package main

import (
	"os"

	protobufs "github.com/crowdsecurity/crowdsec/pkg/protobufs"
	hclog "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
)

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "alertmanager-plugin",
	Level:      hclog.LevelFromString("DEBUG"),
	Output:     os.Stderr,
	JSONFormat: true,
})

type PluginConfig struct {
	Name     string
	LogLevel *string

	Host     string
	BasePath string
	Schemes  []string
	User     string
	Password string
	Source  string
	Team     string
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
			"alertmanager": &protobufs.NotifierPlugin{
				Impl: &AlertmanagerPlugin{
					ConfigByName: make(map[string]PluginConfig),
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
