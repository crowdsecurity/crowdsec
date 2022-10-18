package cwversion

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"

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
	Version             string                  // = "v0.0.0"
	Codename            string                  // = "SoumSoum"
	BuildDate           string                  // = "0000-00-00_00:00:00"
	Tag                 string                  // = "dev"
	GoVersion           = runtime.Version()[2:] // = "1.13"
	System              = runtime.GOOS          // = "linux"
	Constraint_parser   = ">= 1.0, <= 2.0"
	Constraint_scenario = ">= 1.0, < 3.0"
	Constraint_api      = "v1"
	Constraint_acquis   = ">= 1.0, < 2.0"
)

func ShowStr() string {
	ret := ""
	ret += fmt.Sprintf("version: %s-%s\n", Version, Tag)
	ret += fmt.Sprintf("Codename: %s\n", Codename)
	ret += fmt.Sprintf("BuildDate: %s\n", BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", GoVersion)
	ret += fmt.Sprintf("Platform: %s\n", System)
	return ret
}

func Show() {
	log.Printf("version: %s-%s", Version, Tag)
	log.Printf("Codename: %s", Codename)
	log.Printf("BuildDate: %s", BuildDate)
	log.Printf("GoVersion: %s", GoVersion)
	log.Printf("Platform: %s\n", System)
	log.Printf("Constraint_parser: %s", Constraint_parser)
	log.Printf("Constraint_scenario: %s", Constraint_scenario)
	log.Printf("Constraint_api: %s", Constraint_api)
	log.Printf("Constraint_acquis: %s", Constraint_acquis)
}

func VersionStr() string {
	return fmt.Sprintf("%s-%s-%s", Version, System, Tag)
}

func VersionStrip() string {
	version := strings.Split(Version, "-")
	return version[0]
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
