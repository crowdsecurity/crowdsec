package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name       string      `yaml:"name"`
	LogLevel   string      `yaml:"log_level"`
	LogPath    string      `yaml:"log_path"`
	WriteChan  chan string `yaml:"-"`
	FileWriter *os.File    `yaml:"-"`
	LogRotate  LogRotate   `yaml:"rotate"`
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

func Monit(cfg PluginConfig) {
	logger.Trace("Starting monit process")
	queue := make([]string, 0)
	queueMutex := &sync.Mutex{}
	ticker := time.NewTicker(2 * time.Second)
	if cfg.FileWriter == nil {
		cfg.FileWriter, _ = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	for {
		select {
		case <-ticker.C:
			logger.Debug("Checking queue")
			if len(queue) == 0 {
				logger.Debug("Queue is empty")
				continue
			}
			logger.Debug(fmt.Sprintf("Writing %d logs to file", len(queue)))
			newQueue := make([]string, 0, len(queue))
			originalFileInfo, err := cfg.FileWriter.Stat()
			if err != nil {
				logger.Error("Failed to get file info", "error", err)
			}
			for _, log := range queue {
				var err error
				currentFileInfo, _ := os.Stat(cfg.LogPath)
				// Check if the file writer is still pointing to the same file
				if !os.SameFile(originalFileInfo, currentFileInfo) {
					// The file has been rotated
					logger.Info("Log file has been rotated or missing attempting to reopen it")
					cfg.FileWriter.Close()
					cfg.FileWriter, err = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						logger.Error("Failed to reopen log file", "error", err)
						newQueue = append(newQueue, log)
						continue
					}
					logger.Info("Log file has been reopened successfully")
					originalFileInfo, _ = cfg.FileWriter.Stat()
				}
				_, err = cfg.FileWriter.WriteString(log)
				if err != nil {
					logger.Error("Failed to write log", "error", err)
					newQueue = append(newQueue, log)
				}
			}
			cfg.FileWriter.Sync()
			queueMutex.Lock()
			if len(newQueue) > 0 {
				queue = newQueue
			} else {
				queue = make([]string, 0)
			}
			queueMutex.Unlock()
			// TODO! Implement log rotation
			// if cfg.LogRotate.Enabled {
			// 	// check if file size is greater than max size
			// 	fileInfo, _ := cfg.FileWriter.Stat()
			// 	if fileInfo.Size() > int64(cfg.LogRotate.MaxSize) {
			// 		// close file
			// 		cfg.FileWriter.Close()
			// 		// rename file
			// 		os.Rename(cfg.LogPath, cfg.LogPath+".1")
			// 		// open file
			// 		cfg.FileWriter, _ = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			// 		// compress file
			// 		if cfg.LogRotate.Compress {
			// 			// compress file
			// 		}
			// 	}
			// }
		case log := <-cfg.WriteChan:
			logger.Trace("Received log", log)
			queueMutex.Lock()
			queue = append(queue, log)
			queueMutex.Unlock()
		}
	}
}

func (s *FilePlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := s.PluginConfigByName[notification.Name]

	cfg.WriteChan <- notification.Text

	return &protobufs.Empty{}, nil
}

func (s *FilePlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	d.WriteChan = make(chan string)
	s.PluginConfigByName[d.Name] = d
	logger.SetLevel(hclog.LevelFromString(d.LogLevel))
	go Monit(d)
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
