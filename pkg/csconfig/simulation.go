package csconfig

type SimulationConfig struct {
	Simulation *bool    `yaml:"simulation"`
	Exclusions []string `yaml:"exclusions,omitempty"`
}

func (s *SimulationConfig) IsSimulated(scenario string) bool {
	var simulated bool

	if s.Simulation != nil && *s.Simulation {
		simulated = true
	}
	for _, excluded := range s.Exclusions {
		if excluded == scenario {
			simulated = !simulated
			break
		}
	}
	return simulated
}
