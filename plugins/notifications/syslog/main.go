package main

import (
	"context"
	"fmt"
	"log/syslog"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

func (s *PluginConfig) GetPriority() syslog.Priority {
	var priority syslog.Priority
	switch s.Level {
	case "emerg":
		priority = syslog.LOG_EMERG
	case "alert":
		priority = syslog.LOG_ALERT
	case "crit":
		priority = syslog.LOG_CRIT
	case "err":
		priority = syslog.LOG_ERR
	case "warning":
		priority = syslog.LOG_WARNING
	case "notice":
		priority = syslog.LOG_NOTICE
	case "info":
		priority = syslog.LOG_INFO
	case "debug":
		priority = syslog.LOG_DEBUG
	default:
		priority = syslog.LOG_INFO
	}
	return priority | syslog.LOG_DAEMON
}

type PluginConfig struct {
	Name       string         `yaml:"name"`
	LogLevel   *string        `yaml:"log_level"`
	OutputFile *string        `yaml:"output_file"`
	Url        string         `yaml:"url"`
	Protocol   string         `yaml:"protocol"`
	Tag        string         `yaml:"tag"`
	Level      string         `yaml:"level"`
	Writer     *syslog.Writer `yaml:"-"` //not in yaml
}

type SyslogPlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "syslog-plugin",
	Level:      hclog.LevelFromString("info"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (s *SyslogPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Debug(notification.Text)

	if _, err := cfg.Writer.Write([]byte(notification.Text)); err != nil {
		logger.Warn(fmt.Sprintf("failed to write to syslog: %s", err))
	}

	return &protobufs.Empty{}, nil
}

func (s *SyslogPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := error(nil)
	yaml.Unmarshal(config.Config, &d)
	d.Writer, err = syslog.Dial(d.Protocol, d.Url, d.GetPriority(), d.Tag)
	s.PluginConfigByName[d.Name] = d
	return &protobufs.Empty{}, err
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &SyslogPlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"syslog": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
