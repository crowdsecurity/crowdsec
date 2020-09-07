package cwversion

import (
	"fmt"
	"log"

	version "github.com/hashicorp/go-version"
)

/*

Given a version number MAJOR.MINOR.PATCH, increment the:

	MAJOR version when you make incompatible API changes,
	MINOR version when you add functionality in a backwards compatible manner, and
	PATCH version when you make backwards compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

*/

var (
	Version             string // = "v0.0.0"
	Codename            string // = "SoumSoum"
	BuildDate           string // = "I don't remember exactly"
	Tag                 string // = "dev"
	GoVersion           string // = "1.13"
	Constraint_parser   = ">= 1.0, < 2.0"
	Constraint_scenario = ">= 1.0, < 3.0"
	Constraint_api      = "v1"
	Constraint_acquis   = ">= 1.0, < 2.0"
)

func Show() {
	log.Printf("version: %s-%s", Version, Tag)
	log.Printf("Codename: %s", Codename)
	log.Printf("BuildDate: %s", BuildDate)
	log.Printf("GoVersion: %s", GoVersion)
	log.Printf("Constraint_parser: %s", Constraint_parser)
	log.Printf("Constraint_scenario: %s", Constraint_scenario)
	log.Printf("Constraint_api: %s", Constraint_api)
	log.Printf("Constraint_acquis: %s", Constraint_acquis)
}

func VersionStr() string {
	return fmt.Sprintf("%s-%s", Version, Tag)
}

func Statisfies(strvers string, constraint string) (bool, error) {
	vers, err := version.NewVersion(strvers)
	if err != nil {
		return false, fmt.Errorf("failed to parse '%s' : %v", strvers, err)
	}
	constraints, err := version.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("failed to parse constraint '%s'", constraint)
	}
	if !constraints.Check(vers) {
		return false, nil
	}
	return true, nil
}
