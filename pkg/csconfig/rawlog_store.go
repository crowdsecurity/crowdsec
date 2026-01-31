package csconfig

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

type RawLogCfg struct {
	Enabled       *bool  `yaml:"enabled"`
	DbPath        string `yaml:"db_path,omitempty"`
	Retention     string `yaml:"retention,omitempty"`
	QueueSize     int    `yaml:"queue_size,omitempty"`
	BatchSize     int    `yaml:"batch_size,omitempty"`
	FlushInterval string `yaml:"flush_interval,omitempty"`
	CaptureType   string `yaml:"capture_type,omitempty"`

	RetentionDuration     time.Duration `yaml:"-"`
	FlushIntervalDuration time.Duration `yaml:"-"`
}

func (c *Config) LoadRawLogStore() error {
	if c.Crowdsec == nil || c.Crowdsec.RawLog == nil {
		return nil
	}

	rc := c.Crowdsec.RawLog

	if rc.Enabled == nil {
		rc.Enabled = ptr.Of(false)
	}

	if !*rc.Enabled {
		return nil
	}

	if rc.DbPath == "" {
		rc.DbPath = filepath.Join(c.ConfigPaths.DataDir, "accesslogs.db")
	}

	if err := ensureAbsolutePath(&rc.DbPath); err != nil {
		return err
	}

	if rc.Retention == "" {
		rc.Retention = "168h"
	}

	retentionDuration, err := time.ParseDuration(rc.Retention)
	if err != nil {
		return fmt.Errorf("invalid rawlog_store.retention: %w", err)
	}

	if retentionDuration < 0 {
		return fmt.Errorf("rawlog_store.retention must be positive")
	}

	if rc.FlushInterval == "" {
		rc.FlushInterval = "2s"
	}

	flushIntervalDuration, err := time.ParseDuration(rc.FlushInterval)
	if err != nil {
		return fmt.Errorf("invalid rawlog_store.flush_interval: %w", err)
	}

	if flushIntervalDuration <= 0 {
		return fmt.Errorf("rawlog_store.flush_interval must be positive")
	}

	if rc.QueueSize == 0 {
		rc.QueueSize = 10000
	}

	if rc.BatchSize == 0 {
		rc.BatchSize = 200
	}

	if rc.BatchSize > rc.QueueSize {
		rc.BatchSize = rc.QueueSize
	}

	if rc.CaptureType == "" {
		rc.CaptureType = "caddy"
	}

	rc.RetentionDuration = retentionDuration
	rc.FlushIntervalDuration = flushIntervalDuration

	return nil
}
