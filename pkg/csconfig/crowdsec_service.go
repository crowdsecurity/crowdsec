package csconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

/*Configurations needed for crowdsec to load parser/scenarios/... + acquisition*/
type CrowdsecServiceCfg struct {
	AcquisitionFilePath string `yaml:"acquisition_path,omitempty"`
	AcquisitionDirPath  string `yaml:"acquisition_dir,omitempty"`

	AcquisitionFiles     []string          `yaml:"-"`
	ParserRoutinesCount  int               `yaml:"parser_routines"`
	BucketsRoutinesCount int               `yaml:"buckets_routines"`
	OutputRoutinesCount  int               `yaml:"output_routines"`
	SimulationConfig     *SimulationConfig `yaml:"-"`
	LintOnly             bool              `yaml:"-"`                          //if set to true, exit after loading configs
	BucketStateFile      string            `yaml:"state_input_file,omitempty"` //if we need to unserialize buckets at start
	BucketStateDumpDir   string            `yaml:"state_output_dir,omitempty"` //if we need to unserialize buckets on shutdown
	BucketsGCEnabled     bool              `yaml:"-"`                          //we need to garbage collect buckets when in forensic mode

	HubDir             string `yaml:"-"`
	DataDir            string `yaml:"-"`
	ConfigDir          string `yaml:"-"`
	HubIndexFile       string `yaml:"-"`
	SimulationFilePath string `yaml:"-"`
}

func (c *Config) LoadCrowdsec() error {
	var err error
	// Configuration paths are dependency to load crowdsec configuration
	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	if c.Crowdsec == nil {
		c.DisableAgent = true
		return nil
	}
	if c.Crowdsec.AcquisitionFilePath != "" {
		log.Debugf("non-empty acquisition file path %s", c.Crowdsec.AcquisitionFilePath)
		if _, err := os.Stat(c.Crowdsec.AcquisitionFilePath); err != nil {
			return errors.Wrapf(err, "while checking acquisition path %s", c.Crowdsec.AcquisitionFilePath)
		}
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, c.Crowdsec.AcquisitionFilePath)
	}
	if c.Crowdsec.AcquisitionDirPath != "" {
		files, err := filepath.Glob(c.Crowdsec.AcquisitionDirPath + "/*.yaml")
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, files...)
		if err != nil {
			return errors.Wrap(err, "while globing acquis_dir")
		}
	}
	if c.Crowdsec.AcquisitionDirPath == "" && c.Crowdsec.AcquisitionFilePath == "" {
		return fmt.Errorf("no acquisition_path nor acquisition_dir")
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
			return errors.Wrap(err, "failed to clean path")
		}
	}
	for i, file := range c.Crowdsec.AcquisitionFiles {
		f, err := filepath.Abs(file)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
		c.Crowdsec.AcquisitionFiles[i] = f
	}

	if err := c.LoadAPIClient(); err != nil {
		return fmt.Errorf("loading api client: %s", err.Error())
	}
	if err := c.LoadHub(); err != nil {
		return fmt.Errorf("loading hub: %s", err)
	}
	return nil
}
