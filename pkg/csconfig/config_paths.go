package csconfig

type ConfigurationPaths struct {
	ConfigDir          string `yaml:"config_dir"`
	DataDir            string `yaml:"data_dir,omitempty"`
	SimulationFilePath string `yaml:"simulation_path,omitempty"`
	HubIndexFile       string `yaml:"index_path,omitempty"` //path of the .index.json
	HubDir             string `yaml:"hub_dir,omitempty"`
}
