package csconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/ptr"
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
	SimulationConfig          SimulationConfig `yaml:"-"`
	BucketStateFile           string           `yaml:"state_input_file,omitempty"` // if we need to unserialize buckets at start
	BucketStateDumpDir        string           `yaml:"state_output_dir,omitempty"` // if we need to unserialize buckets on shutdown
	BucketsGCEnabled          bool             `yaml:"-"`                          // we need to garbage collect buckets when in forensic mode

	SimulationFilePath string              `yaml:"-"`
	ContextToSend      map[string][]string `yaml:"-"`
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
		c.Crowdsec.Enable = ptr.Of(true)
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

	if c.Crowdsec.ParserRoutinesCount <= 0 {
		c.Crowdsec.ParserRoutinesCount = 1
	}

	if c.Crowdsec.BucketsRoutinesCount <= 0 {
		c.Crowdsec.BucketsRoutinesCount = 1
	}

	if c.Crowdsec.OutputRoutinesCount <= 0 {
		c.Crowdsec.OutputRoutinesCount = 1
	}

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
