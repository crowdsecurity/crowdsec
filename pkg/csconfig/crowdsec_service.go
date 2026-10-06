package csconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// CrowdsecServiceCfg contains the location of parsers/scenarios/... and acquisition files
type CrowdsecServiceCfg struct {
	Enable                    *bool            `yaml:"enable"`
	AcquisitionFilePath       string           `yaml:"acquisition_path,omitempty"`
	AcquisitionDirPath        string           `yaml:"acquisition_dir,omitempty"`
	ConsoleContextPath        string           `yaml:"console_context_path"`
	ConsoleContextValueLength int              `yaml:"console_context_value_length"`
	AcquisitionFiles          []string         `yaml:"-"`
	ParserRoutinesCount       int              `yaml:"parser_routines"`
	BucketsRoutinesCount      int              `yaml:"buckets_routines"`
	OutputRoutinesCount       int              `yaml:"output_routines"`
	Pipeline                  *PipelineCfg     `yaml:"pipeline,omitempty"`
	SimulationConfig          SimulationConfig `yaml:"-"`
	BucketStateFile           string           `yaml:"state_input_file,omitempty"` // if we need to unserialize buckets at start
	BucketStateDumpDir        string           `yaml:"state_output_dir,omitempty"` // if we need to unserialize buckets on shutdown
	BucketsGCEnabled          bool             `yaml:"-"`                          // we need to garbage collect buckets when in forensic mode
	DNSCache                  *DNSCacheCfg     `yaml:"dns_cache,omitempty"`

	SimulationFilePath string              `yaml:"-"`
	ContextToSend      map[string][]string `yaml:"-"`

	PostOverflowQueueSize int `yaml:"-"` // resolved from Pipeline
}

type PipelineStageCfg struct {
	Routines *int `yaml:"routines,omitempty"`
}

// The output stage is the only one with a queue in front of it, for postoverflow.
type PipelineOutputCfg struct {
	Routines  *int `yaml:"routines,omitempty"`
	QueueSize *int `yaml:"queue_size,omitempty"`
}

// Supersedes the flat *_routines keys, which remain the fallback when unset here.
type PipelineCfg struct {
	Parser *PipelineStageCfg  `yaml:"parser,omitempty"`
	Bucket *PipelineStageCfg  `yaml:"bucket,omitempty"`
	Output *PipelineOutputCfg `yaml:"output,omitempty"`
}

// ~30x the worst case burst in #4600 (arrival rate x the 3s dnscache bound), and
// small enough that a stuck pipeline hits the drop counter in minutes.
const defaultPostOverflowQueueSize = 256

// The nested value wins; warn when the legacy key disagrees so it doesn't look effective.
func resolveRoutines(stage string, legacyKey string, cfg *PipelineStageCfg, legacy int) int {
	if cfg == nil || cfg.Routines == nil {
		if legacy <= 0 {
			return 1
		}

		return legacy
	}

	n := *cfg.Routines
	if n <= 0 {
		n = 1
	}

	if legacy > 1 && legacy != n {
		log.Warnf("pipeline.%s.routines (%d) overrides %s (%d)", stage, n, legacyKey, legacy)
	}

	return n
}

func resolveQueueSize(cfg *PipelineOutputCfg, def int) int {
	if cfg == nil || cfg.QueueSize == nil || *cfg.QueueSize <= 0 {
		return def
	}

	return *cfg.QueueSize
}

// Cache config for DNS lookups (legit bots, rdns PO)
type DNSCacheCfg struct {
	TTL         *time.Duration `yaml:"ttl,omitempty"`
	NegativeTTL *time.Duration `yaml:"negative_ttl,omitempty"`
	Size        *int           `yaml:"size,omitempty"`
}

var ErrNoAcquisitionDefined = errors.New("no acquisition_path or acquisition_dir specified")

func (c *CrowdsecServiceCfg) CollectAcquisitionFiles() ([]string, error) {
	ret := []string{}

	// agent section missing in the configuration file.
	// likely a lapi-only setup, not much we can do here
	if c == nil {
		return nil, nil
	}

	if c.AcquisitionFilePath != "" {
		log.Debugf("non-empty acquisition_path %s", c.AcquisitionFilePath)

		_, err := os.Stat(c.AcquisitionFilePath)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			log.Debugf("acquisition_path: %s does not exist, skipping", c.AcquisitionFilePath)
		case err != nil:
			return nil, fmt.Errorf("while checking acquisition_path: %w", err)
		default:
			ret = append(ret, c.AcquisitionFilePath)
		}
	}

	// XXX: TODO: set default AcquisitionDirPath

	if c.AcquisitionDirPath != "" {
		dirFiles, err := filepath.Glob(c.AcquisitionDirPath + "/*.yaml")
		if err != nil {
			return nil, fmt.Errorf("while globbing acquis_dir: %w", err)
		}

		ret = append(ret, dirFiles...)

		dirFiles, err = filepath.Glob(c.AcquisitionDirPath + "/*.yml")
		if err != nil {
			return nil, fmt.Errorf("while globbing acquis_dir: %w", err)
		}

		ret = append(ret, dirFiles...)
	}

	if c.AcquisitionDirPath == "" && c.AcquisitionFilePath == "" {
		return nil, ErrNoAcquisitionDefined
	}

	// files in 'ret' are already absolute

	return ret, nil
}

func (c *Config) LoadCrowdsec() error {
	var err error

	if c.Crowdsec == nil {
		log.Warning("crowdsec agent is disabled")

		c.DisableAgent = true

		return nil
	}

	if c.Crowdsec.Enable == nil {
		// if the option is not present, it is enabled by default
		c.Crowdsec.Enable = new(true)
	}

	if !*c.Crowdsec.Enable {
		log.Warning("crowdsec agent is disabled")
		c.DisableAgent = true
		return nil
	}

	cleanup := []*string{
		&c.Crowdsec.AcquisitionDirPath,
		&c.Crowdsec.AcquisitionFilePath,
		&c.Crowdsec.ConsoleContextPath,
	}

	for _, p := range cleanup {
		if err := ensureAbsolutePath(p); err != nil {
			return err
		}
	}

	acquisitionFiles, err := c.Crowdsec.CollectAcquisitionFiles()

	switch {
	case errors.Is(err, ErrNoAcquisitionDefined):
		log.Warning(err)
		c.Crowdsec.AcquisitionFiles = []string{}
	case err != nil:
		return err
	default:
		c.Crowdsec.AcquisitionFiles = acquisitionFiles
	}

	if err = c.LoadSimulation(); err != nil {
		return fmt.Errorf("load error (simulation): %w", err)
	}

	pipelineCfg := c.Crowdsec.Pipeline
	if pipelineCfg == nil {
		pipelineCfg = &PipelineCfg{}
	}

	c.Crowdsec.ParserRoutinesCount = resolveRoutines("parser", "parser_routines", pipelineCfg.Parser, c.Crowdsec.ParserRoutinesCount)
	c.Crowdsec.BucketsRoutinesCount = resolveRoutines("bucket", "buckets_routines", pipelineCfg.Bucket, c.Crowdsec.BucketsRoutinesCount)
	outputRoutines := &PipelineStageCfg{}
	if pipelineCfg.Output != nil {
		outputRoutines.Routines = pipelineCfg.Output.Routines
	}

	c.Crowdsec.OutputRoutinesCount = resolveRoutines("output", "output_routines", outputRoutines, c.Crowdsec.OutputRoutinesCount)
	c.Crowdsec.PostOverflowQueueSize = resolveQueueSize(pipelineCfg.Output, defaultPostOverflowQueueSize)

	if err = c.LoadAPIClient(); err != nil {
		return fmt.Errorf("loading api client: %w", err)
	}

	return nil
}

func (c *CrowdsecServiceCfg) DumpContextConfigFile() error {
	// XXX: MakeDirs
	out, err := yaml.Marshal(c.ContextToSend)
	if err != nil {
		return fmt.Errorf("while serializing ConsoleConfig (for %s): %w", c.ConsoleContextPath, err)
	}

	if err = os.MkdirAll(filepath.Dir(c.ConsoleContextPath), 0o700); err != nil {
		return fmt.Errorf("while creating directories for %s: %w", c.ConsoleContextPath, err)
	}

	if err := os.WriteFile(c.ConsoleContextPath, out, 0o600); err != nil {
		return fmt.Errorf("while dumping console config to %s: %w", c.ConsoleContextPath, err)
	}

	log.Infof("%s file saved", c.ConsoleContextPath)

	return nil
}
