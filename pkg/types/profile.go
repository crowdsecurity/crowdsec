package types

import (
	"time"

	"github.com/antonmedv/expr/vm"
)

/*Action profiles*/
type RemediationProfile struct {
	Apply        bool
	Ban          bool
	Slow         bool
	Captcha      bool
	Duration     string
	TimeDuration time.Duration
}
type Profile struct {
	Profile       string             `yaml:"profile"`
	Filter        string             `yaml:"filter"`
	Remediation   RemediationProfile `yaml:"remediation"`
	RunTimeFilter *vm.Program
	ApiPush       *bool               `yaml:"api"`
	OutputConfigs []map[string]string `yaml:"outputs,omitempty"`
}
