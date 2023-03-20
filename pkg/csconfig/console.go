package csconfig

import (
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	SEND_CUSTOM_SCENARIOS  = "custom"
	SEND_TAINTED_SCENARIOS = "tainted"
	SEND_MANUAL_SCENARIOS  = "manual"
	CONSOLE_MANAGEMENT     = "console_management"
	SEND_CONTEXT           = "context"
)

var CONSOLE_CONFIGS = []string{SEND_CUSTOM_SCENARIOS, SEND_MANUAL_SCENARIOS, SEND_TAINTED_SCENARIOS, SEND_CONTEXT, CONSOLE_MANAGEMENT}

var DefaultConsoleConfigFilePath = DefaultConfigPath("console.yaml")

type ConsoleConfig struct {
	ShareManualDecisions  *bool `yaml:"share_manual_decisions"`
	ShareTaintedScenarios *bool `yaml:"share_tainted"`
	ShareCustomScenarios  *bool `yaml:"share_custom"`
	ConsoleManagement     *bool `yaml:"console_management"`
	ShareContext          *bool `yaml:"share_context"`
}

func (c *LocalApiServerCfg) LoadConsoleConfig() error {
	c.ConsoleConfig = &ConsoleConfig{}
	if _, err := os.Stat(c.ConsoleConfigPath); err != nil && os.IsNotExist(err) {
		log.Debugf("no console configuration to load")
		c.ConsoleConfig.ShareCustomScenarios = types.BoolPtr(true)
		c.ConsoleConfig.ShareTaintedScenarios = types.BoolPtr(true)
		c.ConsoleConfig.ShareManualDecisions = types.BoolPtr(false)
		c.ConsoleConfig.ConsoleManagement = types.BoolPtr(false)
		c.ConsoleConfig.ShareContext = types.BoolPtr(false)
		return nil
	}

	yamlFile, err := os.ReadFile(c.ConsoleConfigPath)
	if err != nil {
		return fmt.Errorf("reading console config file '%s': %s", c.ConsoleConfigPath, err)
	}
	err = yaml.Unmarshal(yamlFile, c.ConsoleConfig)
	if err != nil {
		return fmt.Errorf("unmarshaling console config file '%s': %s", c.ConsoleConfigPath, err)
	}

	if c.ConsoleConfig.ShareCustomScenarios == nil {
		log.Debugf("no share_custom scenarios found, setting to true")
		c.ConsoleConfig.ShareCustomScenarios = types.BoolPtr(true)
	}
	if c.ConsoleConfig.ShareTaintedScenarios == nil {
		log.Debugf("no share_tainted scenarios found, setting to true")
		c.ConsoleConfig.ShareTaintedScenarios = types.BoolPtr(true)
	}
	if c.ConsoleConfig.ShareManualDecisions == nil {
		log.Debugf("no share_manual scenarios found, setting to false")
		c.ConsoleConfig.ShareManualDecisions = types.BoolPtr(false)
	}

	if !fflag.PapiClient.IsEnabled() {
		c.ConsoleConfig.ConsoleManagement = types.BoolPtr(false)
	} else if c.ConsoleConfig.ConsoleManagement == nil {
		log.Debugf("no console_management found, setting to false")
		c.ConsoleConfig.ConsoleManagement = types.BoolPtr(false)
	}

	if c.ConsoleConfig.ShareContext == nil {
		log.Debugf("no 'context' found, setting to false")
		c.ConsoleConfig.ShareContext = types.BoolPtr(false)
	}

	log.Debugf("Console configuration '%s' loaded successfully", c.ConsoleConfigPath)

	return nil
}

func (c *LocalApiServerCfg) DumpConsoleConfig() error {
	var out []byte
	var err error

	if out, err = yaml.Marshal(c.ConsoleConfig); err != nil {
		return errors.Wrapf(err, "while marshaling ConsoleConfig (for %s)", c.ConsoleConfigPath)
	}
	if c.ConsoleConfigPath == "" {
		c.ConsoleConfigPath = DefaultConsoleConfigFilePath
		log.Debugf("Empty console_path, defaulting to %s", c.ConsoleConfigPath)

	}

	if err := os.WriteFile(c.ConsoleConfigPath, out, 0600); err != nil {
		return errors.Wrapf(err, "while dumping console config to %s", c.ConsoleConfigPath)
	}

	return nil
}
