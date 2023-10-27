package main

// Set the appropriate hub branch according to config settings and crowdsec version

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

// chooseHubBranch returns the branch name to use for the hub
// It can be "master" or the branch corresponding to the current crowdsec version
func chooseHubBranch() string {
	latest, err := cwversion.Latest()
	if err != nil {
		log.Warningf("Unable to retrieve latest crowdsec version: %s, defaulting to master", err)
		return "master"
	}

	csVersion := cwversion.VersionStrip()
	if csVersion == latest {
		log.Debugf("current version is equal to latest (%s)", csVersion)
		return "master"
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", csVersion)
		return "master"
	}

	if csVersion == "" {
		log.Warning("Crowdsec version is not set, using master branch for the hub")
		return "master"
	}

	log.Warnf("Crowdsec is not the latest version. "+
		"Current version is '%s' and the latest stable version is '%s'. Please update it!",
		csVersion, latest)

	log.Warnf("As a result, you will not be able to use parsers/scenarios/collections "+
		"added to Crowdsec Hub after CrowdSec %s", latest)

	return csVersion
}
