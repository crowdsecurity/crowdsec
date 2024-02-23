package cwversion

import (
	"encoding/json"
	"fmt"
	"log"
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
		ret += fmt.Sprintf("-%s", version.Tag)
	}

	return ret
}

func ShowStr() string {
	ret := fmt.Sprintf("version: %s", versionWithTag())
	ret += fmt.Sprintf("Codename: %s\n", Codename)
	ret += fmt.Sprintf("BuildDate: %s\n", version.BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", version.GoVersion)
	ret += fmt.Sprintf("Platform: %s\n", System)

	return ret
}

func Show() {
	log.Printf("version: %s", versionWithTag())
	log.Printf("Codename: %s", Codename)
	log.Printf("BuildDate: %s", version.BuildDate)
	log.Printf("GoVersion: %s", version.GoVersion)
	log.Printf("Platform: %s\n", System)
	log.Printf("libre2: %s\n", Libre2)
	log.Printf("Constraint_parser: %s", Constraint_parser)
	log.Printf("Constraint_scenario: %s", Constraint_scenario)
	log.Printf("Constraint_api: %s", Constraint_api)
	log.Printf("Constraint_acquis: %s", Constraint_acquis)
}

func VersionStr() string {
	return fmt.Sprintf("%s-%s-%s", version.Version, System, version.Tag)
}

func VersionStrip() string {
	version := strings.Split(version.Version, "~")
	version = strings.Split(version[0], "-")

	return version[0]
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
	latest := make(map[string]interface{})

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
