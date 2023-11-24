package csconfig

import (
	"fmt"
	"path/filepath"
)

type ConfigurationPaths struct {
	ConfigDir          string `yaml:"config_dir"`
	DataDir            string `yaml:"data_dir,omitempty"`
	SimulationFilePath string `yaml:"simulation_path,omitempty"`
	HubIndexFile       string `yaml:"index_path,omitempty"` //path of the .index.json
	HubDir             string `yaml:"hub_dir,omitempty"`
	PluginDir          string `yaml:"plugin_dir,omitempty"`
	NotificationDir    string `yaml:"notification_dir,omitempty"`
}

func (c *Config) loadConfigurationPaths() error {
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
		&c.ConfigPaths.PluginDir,
		&c.ConfigPaths.NotificationDir,
	}
	for _, k := range configPathsCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return fmt.Errorf("failed to get absolute path of '%s': %w", *k, err)
		}
	}

	return nil
}
