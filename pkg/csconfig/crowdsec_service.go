package csconfig

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
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
	LintOnly                  bool              `yaml:"-"`                          // if set to true, exit after loading configs
	BucketStateFile           string            `yaml:"state_input_file,omitempty"` // if we need to unserialize buckets at start
	BucketStateDumpDir        string            `yaml:"state_output_dir,omitempty"` // if we need to unserialize buckets on shutdown
	BucketsGCEnabled          bool              `yaml:"-"`                          // we need to garbage collect buckets when in forensic mode

	HubDir             string              `yaml:"-"`
	DataDir            string              `yaml:"-"`
	ConfigDir          string              `yaml:"-"`
	HubIndexFile       string              `yaml:"-"`
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

	c.Crowdsec.ConfigDir = c.ConfigPaths.ConfigDir
	c.Crowdsec.DataDir = c.ConfigPaths.DataDir
	c.Crowdsec.HubDir = c.ConfigPaths.HubDir
	c.Crowdsec.HubIndexFile = c.ConfigPaths.HubIndexFile

	if c.Crowdsec.ParserRoutinesCount <= 0 {
		c.Crowdsec.ParserRoutinesCount = 1
	}

	if c.Crowdsec.BucketsRoutinesCount <= 0 {
		c.Crowdsec.BucketsRoutinesCount = 1
	}

	if c.Crowdsec.OutputRoutinesCount <= 0 {
		c.Crowdsec.OutputRoutinesCount = 1
	}

	var crowdsecCleanup = []*string{
		&c.Crowdsec.AcquisitionFilePath,
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

	if err := c.LoadAPIClient(); err != nil {
		return fmt.Errorf("loading api client: %s", err)
	}

	if err := c.LoadHub(); err != nil {
		return fmt.Errorf("while loading hub: %w", err)
	}

	c.Crowdsec.ContextToSend = make(map[string][]string, 0)
	fallback := false
	if c.Crowdsec.ConsoleContextPath == "" {
		// fallback to default config file
		c.Crowdsec.ConsoleContextPath = filepath.Join(c.Crowdsec.ConfigDir, "console", "context.yaml")
		fallback = true
	}

	f, err := filepath.Abs(c.Crowdsec.ConsoleContextPath)
	if err != nil {
		return fmt.Errorf("fail to get absolute path of %s: %s", c.Crowdsec.ConsoleContextPath, err)
	}

	c.Crowdsec.ConsoleContextPath = f
	yamlFile, err := os.ReadFile(c.Crowdsec.ConsoleContextPath)
	if err != nil {
		if fallback {
			log.Debugf("Default context config file doesn't exist, will not use it")
		} else {
			return fmt.Errorf("failed to open context file: %s", err)
		}
	} else {
		err = yaml.Unmarshal(yamlFile, c.Crowdsec.ContextToSend)
		if err != nil {
			return fmt.Errorf("unmarshaling labels console config file '%s': %s", c.Crowdsec.ConsoleContextPath, err)
		}
	}

	return nil
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
