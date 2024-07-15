package cwversion

import (
	"fmt"
	"strings"

	goversion "github.com/hashicorp/go-version"

	"github.com/crowdsecurity/go-cs-lib/version"
)

var (
	Codename string         // = "SoumSoum"
	Libre2   = "WebAssembly"
)

const (
	Constraint_parser   = ">= 1.0, <= 3.0"
	Constraint_scenario = ">= 1.0, <= 3.0"
	Constraint_api      = "v1"
	Constraint_acquis   = ">= 1.0, < 2.0"
)

func FullString() string {
	ret := fmt.Sprintf("version: %s\n", version.String())
	ret += fmt.Sprintf("Codename: %s\n", Codename)
	ret += fmt.Sprintf("BuildDate: %s\n", version.BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", version.GoVersion)
	ret += fmt.Sprintf("Platform: %s\n", version.System)
	ret += fmt.Sprintf("libre2: %s\n", Libre2)
	ret += fmt.Sprintf("User-Agent: %s\n", UserAgent())
	ret += fmt.Sprintf("Constraint_parser: %s\n", Constraint_parser)
	ret += fmt.Sprintf("Constraint_scenario: %s\n", Constraint_scenario)
	ret += fmt.Sprintf("Constraint_api: %s\n", Constraint_api)
	ret += fmt.Sprintf("Constraint_acquis: %s\n", Constraint_acquis)

	return ret
}

func UserAgent() string {
	return "crowdsec/" + version.String() + "-" + version.System
}

// VersionStrip remove the tag from the version string, used to match with a hub branch
func VersionStrip() string {
	ret := strings.Split(version.Version, "~")
	ret = strings.Split(ret[0], "-")

	return ret[0]
}

func Satisfies(strvers string, constraint string) (bool, error) {
	vers, err := goversion.NewVersion(strvers)
	if err != nil {
		return false, fmt.Errorf("failed to parse '%s': %w", strvers, err)
	}

	constraints, err := goversion.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("failed to parse constraint '%s'", constraint)
	}

	if !constraints.Check(vers) {
		return false, nil
	}

	return true, nil
}
