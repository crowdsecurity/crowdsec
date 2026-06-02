package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	nats "github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

type PluginConfig struct {
	Name        string     `yaml:"name"`
	LogLevel    string     `yaml:"log_level"`
	URL         string     `yaml:"url"`
	Subject     string     `yaml:"subject"`
	Token       string     `yaml:"token"`
	Credentials string     `yaml:"credentials"`
	Conn        *nats.Conn `yaml:"-"` // persistent connection, established in Configure()
}

type NatsPlugin struct {
	protobufs.UnimplementedNotifierServer
	ConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "nats-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func buildNatsConn(cfg PluginConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("crowdsec-notification-nats"),
		nats.Timeout(10 * time.Second),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			logger.Warn("NATS disconnected event", "err", fmt.Sprintf("%v", err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Debug("NATS reconnected event")
		}),
	}

	if cfg.Credentials != "" {
		opts = append(opts, nats.UserCredentials(cfg.Credentials))
	}

	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to NATS : %s", err))
		return nil, fmt.Errorf("failed to connect to NATS at %s: %w", cfg.URL, err)
	}
	logger.Debug(fmt.Sprintf("NATS connection established to %s", cfg.URL))

	return nc, nil
}

func (n *NatsPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	name := notification.GetName()
	cfg, ok := n.ConfigByName[name]

	if !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", name)
	}

	if cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(cfg.LogLevel))
	}

	logger.Debug(fmt.Sprintf("received signal for %s config", name))

	text := notification.GetText()

	if cfg.Conn == nil {
		// Lazy connect: Configure stored the config but couldn't connect at startup.
		// Try to establish the connection now. If it fails, return error so the
		// broker's retry-with-backoff can try again later.
		logger.Warn(fmt.Sprintf("NATS connection missing for %s, attempting lazy connect", name))
		nc, err := buildNatsConn(cfg)
		if err != nil {
			return &protobufs.Empty{}, fmt.Errorf("lazy connect to NATS failed for plugin %s: %w", name, err)
		}
		cfg.Conn = nc
		n.ConfigByName[name] = cfg
	}

	logger.Debug(fmt.Sprintf("making NATS publish to %s", cfg.Subject))

	// Publish is fire-and-forget in NATS. No Flush() needed — it blocks
	// indefinitely during reconnect and is not context-aware, causing
	// goroutine leaks when NATS is down.
	if err := cfg.Conn.Publish(cfg.Subject, []byte(text)); err != nil {
		logger.Error(fmt.Sprintf("Failed to make NATS publish : %s", err))
		return &protobufs.Empty{}, err
	}

	logger.Debug(fmt.Sprintf("notification published successfully to %s", cfg.Subject))

	return &protobufs.Empty{}, nil
}

func (n *NatsPlugin) Configure(_ context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	rawConfig := config.GetConfig()

	d := PluginConfig{}

	if err := yaml.Unmarshal(rawConfig, &d); err != nil {
		return nil, err
	}

	if d.URL == "" {
		return nil, fmt.Errorf("NATS plugin '%s': url is required", d.Name)
	}

	if d.Subject == "" {
		return nil, fmt.Errorf("NATS plugin '%s': subject is required", d.Name)
	}

	// Try to establish persistent NATS connection now, but don't fail
	// if NATS is currently down — store the config anyway and retry
	// on the first Notify() call.
	nc, err := buildNatsConn(d)
	if err != nil {
		logger.Warn(fmt.Sprintf("NATS connection failed for %s, will retry on first notification", d.Name))
	} else {
		d.Conn = nc
	}

	n.ConfigByName[d.Name] = d
	logger.Debug(fmt.Sprintf("NATS plugin '%s' configured for URL '%s'", d.Name, d.URL))

	return &protobufs.Empty{}, nil
}

func main() {
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &NatsPlugin{ConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"nats": &csplugin.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
