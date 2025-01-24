package require

// Set the appropriate hub branch according to config settings and crowdsec version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

// lookupLatest returns the latest crowdsec version based on github
func lookupLatest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := "https://version.crowdsec.net/latest"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create request for %s: %w", url, err)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to send request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	latest := make(map[string]any)

	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		return "", fmt.Errorf("unable to decode response from %s: %w", url, err)
	}

	if _, ok := latest["name"]; !ok {
		return "", fmt.Errorf("unable to find 'name' key in response from %s", url)
	}

	name, ok := latest["name"].(string)
	if !ok {
		return "", fmt.Errorf("unable to convert 'name' key to string in response from %s", url)
	}

	return name, nil
}

func chooseBranch(ctx context.Context, cfg *csconfig.Config) string {
	// this was set from config.yaml or flag
	if cfg.Cscli.HubBranch != "" {
		log.Debugf("Hub override from config: branch '%s'", cfg.Cscli.HubBranch)
		return cfg.Cscli.HubBranch
	}

	latest, err := lookupLatest(ctx)
	if err != nil {
		log.Warningf("Unable to retrieve latest crowdsec version: %s, using hub branch 'master'", err)
		return "master"
	}

	csVersion := cwversion.BaseVersion()
	if csVersion == "" {
		log.Warning("Crowdsec version is not set, using hub branch 'master'")
		return "master"
	}

	if csVersion == latest {
		log.Debugf("Latest crowdsec version (%s), using hub branch 'master'", version.String())
		return "master"
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		log.Debugf("Your current crowdsec version seems to be a pre-release (%s), using hub branch 'master'", version.String())
		return "master"
	}

	log.Warnf("A new CrowdSec release is available (%s). "+
		"Your version is '%s'. Please update it to use new parsers/scenarios/collections.",
		latest, csVersion)

	return csVersion
}

// HubBranch sets the branch (in cscli config) and returns its value
// It can be "master", or the branch corresponding to the current crowdsec version, or the value overridden in config/flag
func HubBranch(ctx context.Context, cfg *csconfig.Config) string {
	branch := chooseBranch(ctx, cfg)

	cfg.Cscli.HubBranch = branch

	return branch
}

func HubURLTemplate(cfg *csconfig.Config) string {
	return cfg.Cscli.HubURLTemplate
}
