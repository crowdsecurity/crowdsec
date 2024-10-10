package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

var (
	FileWriter     *os.File
	FileWriteMutex *sync.Mutex
	FileSize       int64
)

type FileWriteCtx struct {
	Ctx    context.Context
	Writer io.Writer
}

func (w *FileWriteCtx) Write(p []byte) (n int, err error) {
	if err := w.Ctx.Err(); err != nil {
		return 0, err
	}
	return w.Writer.Write(p)
}

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
	protobufs.UnimplementedNotifierServer
	PluginConfigByName map[string]PluginConfig
}

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "file-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

func (r *LogRotate) rotateLogs(cfg PluginConfig) {
	// Rotate the log file
	err := r.rotateLogFile(cfg.LogPath, r.MaxFiles)
	if err != nil {
		logger.Error("Failed to rotate log file", "error", err)
	}
	// Reopen the FileWriter
	FileWriter.Close()
	FileWriter, err = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logger.Error("Failed to reopen log file", "error", err)
	}
	// Reset the file size
	FileInfo, err := FileWriter.Stat()
	if err != nil {
		logger.Error("Failed to get file info", "error", err)
	}
	FileSize = FileInfo.Size()
}

func (r *LogRotate) rotateLogFile(logPath string, maxBackups int) error {
	// Rename the current log file
	backupPath := logPath + "." + time.Now().Format("20060102-150405")
	err := os.Rename(logPath, backupPath)
	if err != nil {
		return err
	}
	glob := logPath + ".*"
	if r.Compress {
		glob = logPath + ".*.gz"
		err = compressFile(backupPath)
		if err != nil {
			return err
		}
	}

	// Remove old backups
	files, err := filepath.Glob(glob)
	if err != nil {
		return err
	}

	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	for i, file := range files {
		logger.Trace("Checking file", "file", file, "index", i, "maxBackups", maxBackups)
		if i >= maxBackups {
			logger.Trace("Removing file as over max backup count", "file", file)
			os.Remove(file)
		} else {
			// Check the age of the file
			fileInfo, err := os.Stat(file)
			if err != nil {
				return err
			}
			age := time.Since(fileInfo.ModTime()).Hours()
			if age > float64(r.MaxAge*24) {
				logger.Trace("Removing file as age was over configured amount", "file", file, "age", age)
				os.Remove(file)
			}
		}
	}

	return nil
}

func compressFile(src string) error {
	// Open the source file for reading
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create the destination file
	dstFile, err := os.Create(src + ".gz")
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Create a gzip writer
	gw := gzip.NewWriter(dstFile)
	defer gw.Close()

	// Read the source file and write its contents to the gzip writer
	_, err = io.Copy(gw, srcFile)
	if err != nil {
		return err
	}

	// Delete the original (uncompressed) backup file
	err = os.Remove(src)
	if err != nil {
		return err
	}

	return nil
}

func WriteToFileWithCtx(ctx context.Context, cfg PluginConfig, log string) error {
	FileWriteMutex.Lock()
	defer FileWriteMutex.Unlock()
	originalFileInfo, err := FileWriter.Stat()
	if err != nil {
		logger.Error("Failed to get file info", "error", err)
	}
	currentFileInfo, _ := os.Stat(cfg.LogPath)
	if !os.SameFile(originalFileInfo, currentFileInfo) {
		// The file has been rotated outside our control
		logger.Info("Log file has been rotated or missing attempting to reopen it")
		FileWriter.Close()
		FileWriter, err = os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		FileInfo, err := FileWriter.Stat()
		if err != nil {
			return err
		}
		FileSize = FileInfo.Size()
		logger.Info("Log file has been reopened successfully")
	}
	n, err := io.WriteString(&FileWriteCtx{Ctx: ctx, Writer: FileWriter}, log)
	if err == nil {
		FileSize += int64(n)
		if FileSize > int64(cfg.LogRotate.MaxSize)*1024*1024 && cfg.LogRotate.Enabled {
			logger.Debug("Rotating log file", "file", cfg.LogPath)
			// Rotate the log file
			cfg.LogRotate.rotateLogs(cfg)
		}
	}
	return err
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
	if err != nil {
		logger.Error("Failed to parse config", "error", err)
		return &protobufs.Empty{}, err
	}
	FileWriteMutex = &sync.Mutex{}
	FileWriter, err = os.OpenFile(d.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logger.Error("Failed to open log file", "error", err)
		return &protobufs.Empty{}, err
	}
	FileInfo, err := FileWriter.Stat()
	if err != nil {
		logger.Error("Failed to get file info", "error", err)
		return &protobufs.Empty{}, err
	}
	FileSize = FileInfo.Size()
	s.PluginConfigByName[d.Name] = d
	logger.SetLevel(hclog.LevelFromString(d.LogLevel))
	return &protobufs.Empty{}, err
}

func main() {
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	sp := &FilePlugin{PluginConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"file": &csplugin.NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
