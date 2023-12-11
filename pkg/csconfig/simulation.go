package csconfig

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

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

func (c *Config) LoadSimulation() error {
	simCfg := SimulationConfig{}
	if c.ConfigPaths.SimulationFilePath == "" {
		c.ConfigPaths.SimulationFilePath = filepath.Clean(c.ConfigPaths.ConfigDir + "/simulation.yaml")
	}

	patcher := yamlpatch.NewPatcher(c.ConfigPaths.SimulationFilePath, ".local")
	rcfg, err := patcher.MergedPatchContent()
	if err != nil {
		return err
	}
	if err := yaml.UnmarshalStrict(rcfg, &simCfg); err != nil {
		return fmt.Errorf("while unmarshaling simulation file '%s' : %s", c.ConfigPaths.SimulationFilePath, err)
	}
	if simCfg.Simulation == nil {
		simCfg.Simulation = new(bool)
	}
	if c.Crowdsec != nil {
		c.Crowdsec.SimulationConfig = &simCfg
	}
	if c.Cscli != nil {
		c.Cscli.SimulationConfig = &simCfg
	}
	return nil
}
