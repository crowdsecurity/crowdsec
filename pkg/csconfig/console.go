package csconfig

import (
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	SEND_CUSTOM_SCENARIOS  = "custom"
	SEND_TAINTED_SCENARIOS = "tainted"
	SEND_MANUAL_SCENARIOS  = "manual"
	SEND_LIVE_DECISIONS    = "live_decisions"
)

var CONSOLE_CONFIGS = []string{SEND_CUSTOM_SCENARIOS, SEND_LIVE_DECISIONS, SEND_MANUAL_SCENARIOS, SEND_TAINTED_SCENARIOS}

type ConsoleConfig struct {
	ShareManualDecisions  *bool `yaml:"share_manual_decisions"`
	ShareTaintedScenarios *bool `yaml:"share_custom"`
	ShareCustomScenarios  *bool `yaml:"share_tainted"`
	ShareDecisions        *bool `yaml:"share_decisions"`
}

func (c *LocalApiServerCfg) LoadConsoleConfig() error {
	c.ConsoleConfig = &ConsoleConfig{}
	if _, err := os.Stat(c.ConsoleConfigPath); err != nil && os.IsNotExist(err) {
		log.Debugf("no console configuration to load")
		return nil
	}

	yamlFile, err := ioutil.ReadFile(c.ConsoleConfigPath)
	if err != nil {
		return fmt.Errorf("reading console config file '%s': %s", c.ConsoleConfigPath, err)
	}
	err = yaml.Unmarshal(yamlFile, c.ConsoleConfig)
	if err != nil {
		return fmt.Errorf("unmarshaling console config file '%s': %s", c.ConsoleConfigPath, err)
	}

	if c.ConsoleConfig.ShareCustomScenarios == nil {
		log.Debugf("no share_custom scenarios found, setting to false")
		c.ConsoleConfig.ShareCustomScenarios = new(bool)
	}
	if c.ConsoleConfig.ShareTaintedScenarios == nil {
		log.Debugf("no share_tainted scenarios found, setting to false")
		c.ConsoleConfig.ShareTaintedScenarios = new(bool)
	}
	if c.ConsoleConfig.ShareManualDecisions == nil {
		log.Debugf("no share_manual scenarios found, setting to false")
		c.ConsoleConfig.ShareManualDecisions = new(bool)
	}
	if c.ConsoleConfig.ShareDecisions == nil {
		log.Debugf("no share_decisions scenarios found, setting to false")
		c.ConsoleConfig.ShareDecisions = new(bool)
	}
	log.Infof("Console configuration '%s' loaded successfully", c.ConsoleConfigPath)

	return nil
}
