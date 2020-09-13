package csconfig

type SimulationConfig struct {
	Simulation bool     `yaml:"simulation"`
	Exclusions []string `yaml:"exclusions,omitempty"`
}
