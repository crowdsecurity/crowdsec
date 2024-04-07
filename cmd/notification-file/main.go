package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

var (
	FileWriter     *os.File
	FileWriteMutex *sync.Mutex
)

type PluginConfig struct {
	Name      string    `yaml:"name"`
	LogLevel  string    `yaml:"log_level"`
	LogPath   string    `yaml:"log_path"`
	LogRotate LogRotate `yaml:"rotate"`
}

type LogRotate struct {
	MaxSize  int  `yaml:"max_size"`
	MaxAge   int  `yaml:"max_age"`
	MaxFiles int  `yaml:"max_files"`
	Enabled  bool `yaml:"enabled"`
	Compress bool `yaml:"compress"`
}

type FilePlugin struct {
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "file-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func WriteToFileWithCtx(ctx context.Context, cfg PluginConfig, log string) error {
	for {
		select {
		case <-ctx.Done():
			logger.Error("Context is cancelled")
			return nil
		default:
			if !FileWriteMutex.TryLock() {
				continue
			}
			defer FileWriteMutex.Unlock()
			originalFileInfo, err := FileWriter.Stat()
			if err != nil {
				logger.Error("Failed to get file info", "error", err)
			}
			currentFileInfo, _ := os.Stat(cfg.LogPath)
			if !os.SameFile(originalFileInfo, currentFileInfo) {
				// The file has been rotated
				logger.Info("Log file has been rotated or missing attempting to reopen it")
				FileWriter.Close()
				FileWriter, err = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					return err
				}
				logger.Info("Log file has been reopened successfully")
			}
			_, err = FileWriter.WriteString(log)
			return err
		}
	}
}

func (s *FilePlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	return &protobufs.Empty{}, WriteToFileWithCtx(ctx, cfg, notification.Text)
}

func (s *FilePlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	if err == nil {
		FileWriteMutex = &sync.Mutex{}
		FileWriter, err = os.OpenFile(d.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		s.PluginConfigByName[d.Name] = d
		logger.SetLevel(hclog.LevelFromString(d.LogLevel))
	}
	return &protobufs.Empty{}, err
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &FilePlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"file": &protobufs.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
