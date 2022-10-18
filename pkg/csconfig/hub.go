package csconfig

/*cscli specific config, such as hub directory*/
type Hub struct {
	HubDir       string `yaml:"-"`
	ConfigDir    string `yaml:"-"`
	HubIndexFile string `yaml:"-"`
	DataDir      string `yaml:"-"`
}

func (c *Config) LoadHub() error {
	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	c.Hub = &Hub{
		HubIndexFile: c.ConfigPaths.HubIndexFile,
		ConfigDir:    c.ConfigPaths.ConfigDir,
		HubDir:       c.ConfigPaths.HubDir,
		DataDir:      c.ConfigPaths.DataDir,
	}

	return nil
}
