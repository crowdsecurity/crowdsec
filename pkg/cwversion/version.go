package cwversion

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdsecurity/go-cs-lib/maptools"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/constraint"
)

var (
	Codename string // = "SoumSoum"
	Libre2   = "WebAssembly"
)

func FullString() string {
	dsBuilt := map[string]struct{}{}
	dsExcluded := map[string]struct{}{}

	for ds, built := range component.Built {
		if built {
			dsBuilt[ds] = struct{}{}
			continue
		}

		dsExcluded[ds] = struct{}{}
	}

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

	built := "(none)"

	if len(dsBuilt) > 0 {
		built = strings.Join(maptools.SortedKeys(dsBuilt), ", ")
	}

	ret += fmt.Sprintf("Built-in optional components: %s\n", built)

	if len(dsExcluded) > 0 {
		ret += fmt.Sprintf("Excluded components: %s\n", strings.Join(maptools.SortedKeys(dsExcluded), ", "))
	}

	return ret
}

// StripTags removes any tag (-rc, ~foo3, .r1, etc) from a version string
func StripTags(version string) string {
	reVersion := regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)`)
	ret := reVersion.FindStringSubmatch(version)

	if len(ret) == 0 {
		return version
	}

	return ret[0]
}

// BaseVersion returns the version number used to match a hub branch.
func BaseVersion() string {
	return StripTags(version.Version)
}
