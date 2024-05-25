package cwversion

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	goversion "github.com/hashicorp/go-version"

	"github.com/crowdsecurity/go-cs-lib/version"
)

var (
	Codename string         // = "SoumSoum"
	System   = runtime.GOOS // = "linux"
	Libre2   = "WebAssembly"
)

const (
	Constraint_parser   = ">= 1.0, <= 3.0"
	Constraint_scenario = ">= 1.0, <= 3.0"
	Constraint_api      = "v1"
	Constraint_acquis   = ">= 1.0, < 2.0"
)

func versionWithTag() string {
	ret := version.Version

	if !strings.HasSuffix(ret, version.Tag) {
		ret += "-" + version.Tag
	}

	return ret
}

func FullString() string {
	ret := fmt.Sprintf("version: %s\n", versionWithTag())
	ret += fmt.Sprintf("Codename: %s\n", Codename)
	ret += fmt.Sprintf("BuildDate: %s\n", version.BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", version.GoVersion)
	ret += fmt.Sprintf("Platform: %s\n", System)
	ret += fmt.Sprintf("libre2: %s\n", Libre2)
	ret += fmt.Sprintf("Constraint_parser: %s\n", Constraint_parser)
	ret += fmt.Sprintf("Constraint_scenario: %s\n", Constraint_scenario)
	ret += fmt.Sprintf("Constraint_api: %s\n", Constraint_api)
	ret += fmt.Sprintf("Constraint_acquis: %s\n", Constraint_acquis)

	return ret
}

func VersionStr() string {
	return fmt.Sprintf("%s-%s-%s", version.Version, System, version.Tag)
}

func VersionStrip() string {
	ret := strings.Split(version.Version, "~")
	ret = strings.Split(ret[0], "-")

	return ret[0]
}

func Satisfies(strvers string, constraint string) (bool, error) {
	vers, err := goversion.NewVersion(strvers)
	if err != nil {
		return false, fmt.Errorf("failed to parse '%s' : %v", strvers, err)
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

// Latest return latest crowdsec version based on github
func Latest() (string, error) {
	latest := make(map[string]any)

	resp, err := http.Get("https://version.crowdsec.net/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&latest)
	if err != nil {
		return "", err
	}

	if _, ok := latest["name"]; !ok {
		return "", fmt.Errorf("unable to find latest release name from github api: %+v", latest)
	}

	return latest["name"].(string), nil
}
