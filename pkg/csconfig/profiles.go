package csconfig

import (
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

//Profile structure(s) are used by the local API to "decide" what kind of decision should be applied when a scenario with an active remediation has been triggered
type ProfileCfg struct {
	Name           string   `yaml:"name,omitempty"`
	Debug          *bool    `yaml:"debug,omitempty"`
	Filters        []string `yaml:"filters,omitempty"` //A list of OR'ed expressions. the models.Alert object
	RuntimeFilters []*vm.Program
	DebugFilters   []*exprhelpers.ExprDebugger
	Decisions      []models.Decision `yaml:"decisions,omitempty"`
	OnSuccess      string            `yaml:"on_success,omitempty"` //continue or break
	OnFailure      string            `yaml:"on_failure,omitempty"` //continue or break
}
