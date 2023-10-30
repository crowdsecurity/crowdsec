package require

// Set the appropriate hub branch according to config settings and crowdsec version

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func chooseBranch(cfg *csconfig.Config, logger *log.Logger) string {
	if cfg.Cscli.HubBranch != "" {
		logger.Debugf("Hub override from config: branch '%s'", cfg.Cscli.HubBranch)
		return cfg.Cscli.HubBranch
	}

	latest, err := cwversion.Latest()
	if err != nil {
		logger.Warningf("Unable to retrieve latest crowdsec version: %s, using hub branch 'master'", err)
		return "master"
	}

	csVersion := cwversion.VersionStrip()
	if csVersion == latest {
		logger.Debugf("Latest crowdsec version (%s), using hub branch 'master'", csVersion)
		return "master"
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		logger.Debugf("Your current crowdsec version seems to be a pre-release (%s), using hub branch 'master'", csVersion)
		return "master"
	}

	if csVersion == "" {
		logger.Warning("Crowdsec version is not set, using hub branch 'master'")
		return "master"
	}

	log.Warnf("A new CrowdSec release is available (%s). "+
		"Your version is '%s'. Please update it to use new parsers/scenarios/collections.",
		latest, csVersion)
	return csVersion
}


// HubBranch sets the branch (in cscli config) and returns its value
// It can be "master", or the branch corresponding to the current crowdsec version, or the value overridden in config/flag
func HubBranch(cfg *csconfig.Config) string {
	// XXX: we want to be able to suppress logs
	// to avoid being too noisy in some commands
	logger := log.StandardLogger()

	branch := chooseBranch(cfg, logger)

	cfg.Cscli.HubBranch = branch

	return branch
}
