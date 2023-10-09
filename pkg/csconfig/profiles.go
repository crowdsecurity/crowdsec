package csconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/yamlpatch"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// var OnErrorDefault = OnErrorIgnore
// var OnErrorContinue = "continue"
// var OnErrorBreak = "break"
// var OnErrorApply = "apply"
// var OnErrorIgnore = "ignore"

// Profile structure(s) are used by the local API to "decide" what kind of decision should be applied when a scenario with an active remediation has been triggered
type ProfileCfg struct {
	Name          string            `yaml:"name,omitempty"`
	Debug         *bool             `yaml:"debug,omitempty"`
	Filters       []string          `yaml:"filters,omitempty"` //A list of OR'ed expressions. the models.Alert object
	Decisions     []models.Decision `yaml:"decisions,omitempty"`
	DurationExpr  string            `yaml:"duration_expr,omitempty"`
	OnSuccess     string            `yaml:"on_success,omitempty"` //continue or break
	OnFailure     string            `yaml:"on_failure,omitempty"` //continue or break
	OnError       string            `yaml:"on_error,omitempty"`   //continue, break, error, report, apply, ignore
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

	dec := yaml.NewDecoder(reader)
	dec.SetStrict(true)
	for {
		t := ProfileCfg{}
		err = dec.Decode(&t)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("while decoding %s: %w", c.ProfilesPath, err)
		}
		c.Profiles = append(c.Profiles, &t)
	}

	if len(c.Profiles) == 0 {
		return fmt.Errorf("zero profiles loaded for LAPI")
	}
	return nil
}
