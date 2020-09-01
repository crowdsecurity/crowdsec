package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	log "github.com/sirupsen/logrus"
)

func inSlice(s string, slice []string) bool {
	for _, str := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func indexOf(s string, slice []string) int {
	for i, elem := range slice {
		if s == elem {
			return i
		}
	}
	return -1
}

func setHubBranch() error {
	/*
		if no branch has been specified in flags for the hub, then use the one corresponding to crowdsec version
	*/

	if cwhub.HubBranch == "" {
		latest, err := cwversion.Latest()
		if err != nil {
			cwhub.HubBranch = "master"
			return err
		}

		if cwversion.Version == latest {
			cwhub.HubBranch = "master"
		} else {
			log.Warnf("Crowdsec is not the latest version. Current version is '%s' and latest version is '%s'. Please update it!", cwversion.Version, latest)
			log.Warnf("As a result, you will not be able to use parsers/scenarios/collections added to Crowdsec Hub after CrowdSec %s", latest)
			cwhub.HubBranch = cwversion.Version
		}
		log.Debugf("Using branch '%s' for the hub", cwhub.HubBranch)
	}
	return nil
}
