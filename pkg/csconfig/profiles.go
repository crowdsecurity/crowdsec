package csconfig

import (
	"fmt"
	"io"
	"os"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

//Profile structure(s) are used by the local API to "decide" what kind of decision should be applied when a scenario with an active remediation has been triggered
type ProfileCfg struct {
	Name           string                      `yaml:"name,omitempty"`
	Debug          *bool                       `yaml:"debug,omitempty"`
	Filters        []string                    `yaml:"filters,omitempty"` //A list of OR'ed expressions. the models.Alert object
	RuntimeFilters []*vm.Program               `json:"-"`
	DebugFilters   []*exprhelpers.ExprDebugger `json:"-"`
	Decisions      []models.Decision           `yaml:"decisions,omitempty"`
	OnSuccess      string                      `yaml:"on_success,omitempty"` //continue or break
	OnFailure      string                      `yaml:"on_failure,omitempty"` //continue or break
}

func (c *LocalApiServerCfg) LoadProfiles() error {
	if c.ProfilesPath == "" {
		return fmt.Errorf("empty profiles path")
	}

	yamlFile, err := os.Open(c.ProfilesPath)
	if err != nil {
		return errors.Wrapf(err, "while opening %s", c.ProfilesPath)
	}

	//process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		t := ProfileCfg{}
		err = dec.Decode(&t)
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "while decoding %s", c.ProfilesPath)
		}
		c.Profiles = append(c.Profiles, &t)
	}

	for pIdx, profile := range c.Profiles {
		var runtimeFilter *vm.Program
		var debugFilter *exprhelpers.ExprDebugger

		c.Profiles[pIdx].RuntimeFilters = make([]*vm.Program, len(profile.Filters))
		c.Profiles[pIdx].DebugFilters = make([]*exprhelpers.ExprDebugger, len(profile.Filters))

		for fIdx, filter := range profile.Filters {
			if runtimeFilter, err = expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				return errors.Wrapf(err, "Error compiling filter of %s", profile.Name)
			}
			c.Profiles[pIdx].RuntimeFilters[fIdx] = runtimeFilter
			if debugFilter, err = exprhelpers.NewDebugger(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				log.Debugf("Error compiling debug filter of %s : %s", profile.Name, err)
				// Don't fail if we can't compile the filter - for now
				//	return errors.Wrapf(err, "Error compiling debug filter of %s", profile.Name)
			}
			c.Profiles[pIdx].DebugFilters[fIdx] = debugFilter
		}
	}
	if len(c.Profiles) == 0 {
		return fmt.Errorf("zero profiles loaded for LAPI")
	}
	return nil
}
