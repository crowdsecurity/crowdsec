package csconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

// CrowdsecServiceCfg contains the location of parsers/scenarios/... and acquisition files
type CrowdsecServiceCfg struct {
	Enable                    *bool             `yaml:"enable"`
	AcquisitionFilePath       string            `yaml:"acquisition_path,omitempty"`
	AcquisitionDirPath        string            `yaml:"acquisition_dir,omitempty"`
	ConsoleContextPath        string            `yaml:"console_context_path"`
	ConsoleContextValueLength int               `yaml:"console_context_value_length"`
	AcquisitionFiles          []string          `yaml:"-"`
	ParserRoutinesCount       int               `yaml:"parser_routines"`
	BucketsRoutinesCount      int               `yaml:"buckets_routines"`
	OutputRoutinesCount       int               `yaml:"output_routines"`
	SimulationConfig          *SimulationConfig `yaml:"-"`
	BucketStateFile           string            `yaml:"state_input_file,omitempty"` // if we need to unserialize buckets at start
	BucketStateDumpDir        string            `yaml:"state_output_dir,omitempty"` // if we need to unserialize buckets on shutdown
	BucketsGCEnabled          bool              `yaml:"-"`                          // we need to garbage collect buckets when in forensic mode

	SimulationFilePath string              `yaml:"-"`
	ContextToSend      map[string][]string `yaml:"-"`
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

	if c.Crowdsec.AcquisitionFiles == nil {
		c.Crowdsec.AcquisitionFiles = []string{}
	}

	if c.Crowdsec.AcquisitionFilePath != "" {
		log.Debugf("non-empty acquisition_path %s", c.Crowdsec.AcquisitionFilePath)
		if _, err = os.Stat(c.Crowdsec.AcquisitionFilePath); err != nil {
			return fmt.Errorf("while checking acquisition_path: %w", err)
		}
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, c.Crowdsec.AcquisitionFilePath)
	}

	if c.Crowdsec.AcquisitionDirPath != "" {
		c.Crowdsec.AcquisitionDirPath, err = filepath.Abs(c.Crowdsec.AcquisitionDirPath)
		if err != nil {
			return fmt.Errorf("can't get absolute path of '%s': %w", c.Crowdsec.AcquisitionDirPath, err)
		}

		var files []string

		files, err = filepath.Glob(c.Crowdsec.AcquisitionDirPath + "/*.yaml")
		if err != nil {
			return fmt.Errorf("while globbing acquis_dir: %w", err)
		}
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, files...)

		files, err = filepath.Glob(c.Crowdsec.AcquisitionDirPath + "/*.yml")
		if err != nil {
			return fmt.Errorf("while globbing acquis_dir: %w", err)
		}
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, files...)
	}

	if c.Crowdsec.AcquisitionDirPath == "" && c.Crowdsec.AcquisitionFilePath == "" {
		log.Warning("no acquisition_path or acquisition_dir specified")
	}

	if len(c.Crowdsec.AcquisitionFiles) == 0 {
		log.Warning("no acquisition file found")
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

	crowdsecCleanup := []*string{
		&c.Crowdsec.AcquisitionFilePath,
		&c.Crowdsec.ConsoleContextPath,
	}

	for _, k := range crowdsecCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return fmt.Errorf("failed to get absolute path of '%s': %w", *k, err)
		}
	}

	// Convert relative paths to absolute paths
	for i, file := range c.Crowdsec.AcquisitionFiles {
		f, err := filepath.Abs(file)
		if err != nil {
			return fmt.Errorf("failed to get absolute path of '%s': %w", file, err)
		}
		c.Crowdsec.AcquisitionFiles[i] = f
	}

	if err = c.LoadAPIClient(); err != nil {
		return fmt.Errorf("loading api client: %s", err)
	}

	if c.Crowdsec.ConsoleContextPath != "" {
		// if it's provided, it must exist
		if _, err = os.Stat(c.Crowdsec.ConsoleContextPath); err != nil {
			return fmt.Errorf("while checking console_context_path: %w", err)
		}
	} else {
		c.Crowdsec.ConsoleContextPath = filepath.Join(c.ConfigPaths.ConfigDir, "console", "context.yaml")
	}

	c.Crowdsec.ContextToSend, err = buildContextToSend(c)
	if err != nil {
		return err
	}

	return nil
}

func buildContextToSend(c *Config) (map[string][]string, error) {
	ret := make(map[string][]string, 0)

	log.Tracef("loading console context from %s", c.Crowdsec.ConsoleContextPath)
	content, err := os.ReadFile(c.Crowdsec.ConsoleContextPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to open context file: %s", err)
	}

	err = yaml.Unmarshal(content, ret)
	if err != nil {
		return nil, fmt.Errorf("while loading context from %s: %s", c.Crowdsec.ConsoleContextPath, err)
	}

	feedback, err := json.Marshal(ret)
	if err != nil {
		return nil, fmt.Errorf("marshaling console context: %s", err)
	}

	log.Debugf("console context to send: %s", feedback)

	return ret, nil
}

func (c *CrowdsecServiceCfg) DumpContextConfigFile() error {
	var out []byte
	var err error

	if out, err = yaml.Marshal(c.ContextToSend); err != nil {
		return fmt.Errorf("while marshaling ConsoleConfig (for %s): %w", c.ConsoleContextPath, err)
	}

	if err := os.WriteFile(c.ConsoleContextPath, out, 0600); err != nil {
		return fmt.Errorf("while dumping console config to %s: %w", c.ConsoleContextPath, err)
	}

	log.Infof("%s file saved", c.ConsoleContextPath)

	return nil
}
