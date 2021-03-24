package csconfig

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
)

type ConfigurationPaths struct {
	ConfigDir          string `yaml:"config_dir"`
	DataDir            string `yaml:"data_dir,omitempty"`
	SimulationFilePath string `yaml:"simulation_path,omitempty"`
	HubIndexFile       string `yaml:"index_path,omitempty"` //path of the .index.json
	HubDir             string `yaml:"hub_dir,omitempty"`
}

func (c *Config) LoadConfigurationPaths() error {
	var err error
	if c.ConfigPaths == nil {
		return fmt.Errorf("no configuration paths provided")
	}

	if c.ConfigPaths.DataDir == "" {
		return fmt.Errorf("please provide a data directory with the 'data_dir' directive in the 'config_paths' section")
	}

	if c.ConfigPaths.HubDir == "" {
		c.ConfigPaths.HubDir = filepath.Clean(c.ConfigPaths.ConfigDir + "/hub")
	}

	if c.ConfigPaths.HubIndexFile == "" {
		c.ConfigPaths.HubIndexFile = filepath.Clean(c.ConfigPaths.HubDir + "/.index.json")
	}

	var configPathsCleanup = []*string{
		&c.ConfigPaths.HubDir,
		&c.ConfigPaths.HubIndexFile,
		&c.ConfigPaths.ConfigDir,
		&c.ConfigPaths.DataDir,
		&c.ConfigPaths.SimulationFilePath,
	}
	for _, k := range configPathsCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
	}

	return nil
}
