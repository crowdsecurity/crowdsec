package csconfig

/*cscli specific config, such as hub directory*/
type Hub struct {
	HubIndexFile   string
	HubDir         string
	InstallDir     string
	InstallDataDir string
}

func (c *Config) LoadHub() error {
	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	c.Hub = &Hub{
		HubIndexFile:   c.ConfigPaths.HubIndexFile,
		HubDir:         c.ConfigPaths.HubDir,
		InstallDir:     c.ConfigPaths.ConfigDir,
		InstallDataDir: c.ConfigPaths.DataDir,
	}

	return nil
}
