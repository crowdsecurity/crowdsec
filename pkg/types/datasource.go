package types

import (
	"time"
)

type DataSource struct {
	SourceURL string `yaml:"source_url"`
	DestPath  string `yaml:"dest_file"`
	Type      string `yaml:"type"`
	//Control cache strategy on expensive regexps
	Cache    *bool          `yaml:"cache"`
	Strategy *string        `yaml:"strategy"`
	Size     *int           `yaml:"size"`
	TTL      *time.Duration `yaml:"ttl"`
}
