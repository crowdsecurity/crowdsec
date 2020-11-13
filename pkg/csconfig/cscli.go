package csconfig

/*cscli specific config, such as hub directory*/
type CscliCfg struct {
	Output             string            `yaml:"output,omitempty"`
	HubBranch          string            `yaml:"hub_branch"`
	SimulationConfig   *SimulationConfig `yaml:"-"`
	DbConfig           *DatabaseCfg      `yaml:"-"`
	HubDir             string            `yaml:"-"`
	DataDir            string            `yaml:"-"`
	ConfigDir          string            `yaml:"-"`
	HubIndexFile       string            `yaml:"-"`
	SimulationFilePath string            `yaml:"-"`
}
