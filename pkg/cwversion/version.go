package cwversion

import (
	"fmt"
	"strings"

	"github.com/crowdsecurity/go-cs-lib/maptools"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/constraint"
)

var (
	Codename string // = "SoumSoum"
	Libre2   = "WebAssembly"
)

func FullString() string {
	ret := fmt.Sprintf("version: %s\n", version.String())
	ret += fmt.Sprintf("Codename: %s\n", Codename)
	ret += fmt.Sprintf("BuildDate: %s\n", version.BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", version.GoVersion)
	ret += fmt.Sprintf("Platform: %s\n", version.System)
	ret += fmt.Sprintf("libre2: %s\n", Libre2)
	ret += fmt.Sprintf("User-Agent: %s\n", useragent.Default())
	ret += fmt.Sprintf("Constraint_parser: %s\n", constraint.Parser)
	ret += fmt.Sprintf("Constraint_scenario: %s\n", constraint.Scenario)
	ret += fmt.Sprintf("Constraint_api: %s\n", constraint.API)
	ret += fmt.Sprintf("Constraint_acquis: %s\n", constraint.Acquis)
	ret += fmt.Sprintf("Acquisition data sources: %s\n", strings.Join(maptools.SortedKeys(acquisition.AcquisitionSources), ", "))

	return ret
}

// VersionStrip remove the tag from the version string, used to match with a hub branch
func VersionStrip() string {
	ret := strings.Split(version.Version, "~")
	ret = strings.Split(ret[0], "-")

	return ret[0]
}
