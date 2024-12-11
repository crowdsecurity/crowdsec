package csconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"gopkg.in/yaml.v3"

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
			return !simulated
		}
	}

	return simulated
}

func (c *Config) LoadSimulation() error {
	simCfg := SimulationConfig{}

	if c.ConfigPaths.SimulationFilePath == "" {
		c.ConfigPaths.SimulationFilePath = filepath.Join(c.ConfigPaths.ConfigDir, "simulation.yaml")
	}

	patcher := yamlpatch.NewPatcher(c.ConfigPaths.SimulationFilePath, ".local")

	rcfg, err := patcher.MergedPatchContent()
	if err != nil {
		return err
	}

	dec := yaml.NewDecoder(bytes.NewReader(rcfg))
	dec.KnownFields(true)

	if err := dec.Decode(&simCfg); err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("while parsing simulation file '%s': %w", c.ConfigPaths.SimulationFilePath, err)
		}
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
