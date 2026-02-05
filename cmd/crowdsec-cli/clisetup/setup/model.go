package setup

import (
	"strings"

	"github.com/expr-lang/expr/vm"
)

// DetectConfig contains a set of supported service profiles, loaded from detect.yaml.
type DetectConfig struct {
	Detect map[string]ServiceProfile `yaml:"detect"`
}

// ServiceProfile contains the rules to detect a running service and the suggested configuration to support it from CrowdSec.
// The same software can have multiple profiles, for example, a service running on a systemd unit and another one running as a simple process.
// They will be detected by different rules, will need the same hub items but possibly different acquisition configuration (journalctl vs log file).
type ServiceProfile struct {
	InstallRecommendation `yaml:",inline"`

	// The conditions are evaluated in order, they must all be true for the service to be detected, and there is no short-circuiting.
	When         []string `yaml:"when"`
	compiledWhen []*vm.Program
}

// InstallRecommendation contains the items and acquisition configuration that should be installed to support a service.
type InstallRecommendation struct {
	HubSpec         HubSpec         `yaml:"hub_spec,omitempty"`
	AcquisitionSpec AcquisitionSpec `yaml:"acquisition_spec,omitempty"`
}

// HubSpec is a map of hub_type -> slice of item names. Most of the times, the hub_type is "collection".
// All the items in the slice are installed with their dependencies and data files.
type HubSpec map[string][]string

// AcquisitionSpec contains the datasource configuration to support a detected service.
// The configuration is copied as is, after some static validation depending on the datasource type.
type AcquisitionSpec struct {
	Filename   string
	Datasource DatasourceConfig
}

func (a *AcquisitionSpec) Validate() error {
	if a.Filename == "" {
		if len(a.Datasource) == 0 {
			// missing acquisition is ok - only hub items
			return nil
		}

		// if a datasource is specified, we must have a filename
		return ErrMissingAcquisitionFilename
	}

	if strings.ContainsAny(a.Filename, "/\\") {
		return ErrInvalidAcquisitionFilename
	}

	// check the rest of the spec
	return a.Datasource.Validate()
}

type DatasourceConfig map[string]any

// Setup corresponds to the setup.yaml file. It is used as an intermediary step between "detect" and "install hub/acquisition".
type Setup struct {
	Plans []ServicePlan `yaml:"setup"`
}

// ServicePlan describes the actions to perform for a detected service.
type ServicePlan struct {
	Name                  string `yaml:"detected_service"`
	InstallRecommendation `yaml:",inline"`
}

// DetectOptions contains additional options for the detection process.
type DetectOptions struct {
	SkipServices []string // slice of service specs that will be ignored. detection will happen anyway to spot possible errors.
	WantServices []string // slice of service specs that will be forced.
	SkipSystemd  bool     // ignore all systemd services. the others can still be detected by process name lookup or other mechanism.
}
