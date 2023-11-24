package csconfig

// LocalHubCfg holds the configuration for a local hub: where to download etc.
type LocalHubCfg struct {
	HubIndexFile   string	// Path to the local index file
	HubDir         string	// Where the hub items are downloaded
	InstallDir     string	// Where to install items
	InstallDataDir string	// Where to install data
}

func (c *Config) loadHub() error {
	c.Hub = &LocalHubCfg{
		HubIndexFile:   c.ConfigPaths.HubIndexFile,
		HubDir:         c.ConfigPaths.HubDir,
		InstallDir:     c.ConfigPaths.ConfigDir,
		InstallDataDir: c.ConfigPaths.DataDir,
	}

	return nil
}
