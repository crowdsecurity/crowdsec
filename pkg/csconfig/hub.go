package csconfig

// HubConfig holds the configuration for a hub
type HubCfg struct {
	HubIndexFile   string	// Path to the local index file
	HubDir         string	// Where the hub items are downloaded
	InstallDir     string	// Where to install items
	InstallDataDir string	// Where to install data
}

func (c *Config) LoadHub() error {
	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	c.Hub = &HubCfg{
		HubIndexFile:   c.ConfigPaths.HubIndexFile,
		HubDir:         c.ConfigPaths.HubDir,
		InstallDir:     c.ConfigPaths.ConfigDir,
		InstallDataDir: c.ConfigPaths.DataDir,
	}

	return nil
}
