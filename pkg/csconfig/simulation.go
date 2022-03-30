package csconfig

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
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

	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	simCfg := SimulationConfig{}
	if c.ConfigPaths.SimulationFilePath == "" {
		c.ConfigPaths.SimulationFilePath = filepath.Clean(c.ConfigPaths.ConfigDir + "/simulation.yaml")
	}
	rcfg, err := ioutil.ReadFile(c.ConfigPaths.SimulationFilePath)
	if err != nil {
		return errors.Wrapf(err, "while reading '%s'", c.ConfigPaths.SimulationFilePath)
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
