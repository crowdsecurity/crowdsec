package csconfig

import (
	"bytes"
	"fmt"
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/yamlpatch"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Profile structure(s) are used by the local API to "decide" what kind of decision should be applied when a scenario with an active remediation has been triggered
type ProfileCfg struct {
	Name          string            `yaml:"name,omitempty"`
	Debug         *bool             `yaml:"debug,omitempty"`
	Filters       []string          `yaml:"filters,omitempty"` // A list of OR'ed expressions. the models.Alert object
	Decisions     []models.Decision `yaml:"decisions,omitempty"`
	DurationExpr  string            `yaml:"duration_expr,omitempty"`
	OnSuccess     string            `yaml:"on_success,omitempty"` // continue or break
	OnFailure     string            `yaml:"on_failure,omitempty"` // continue or break
	Notifications []string          `yaml:"notifications,omitempty"`
}

func (c *LocalApiServerCfg) LoadProfiles() error {
	if c.ProfilesPath == "" {
		return fmt.Errorf("empty profiles path")
	}

	patcher := yamlpatch.NewPatcher(c.ProfilesPath, ".local")
	fcontent, err := patcher.PrependedPatchContent()
	if err != nil {
		return err
	}
	reader := bytes.NewReader(fcontent)

	// process the yaml
	dec := yaml.NewDecoder(reader)
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

	if len(c.Profiles) == 0 {
		return fmt.Errorf("zero profiles loaded for LAPI")
	}
	return nil
}
