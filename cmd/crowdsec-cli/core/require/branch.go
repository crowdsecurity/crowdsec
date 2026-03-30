package require

// Set the appropriate hub branch according to config settings and crowdsec version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v5"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

// lookupLatest returns the latest crowdsec version based on github
func lookupLatest(ctx context.Context) (string, error) {
	bo := backoff.NewConstantBackOff(1 * time.Second)

	url := "https://version.crowdsec.net/latest"

	client := &http.Client{}

	operation := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("unable to create request for %s: %w", url, err)
		}

		req.Header.Set("User-Agent", useragent.Default())

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to send request to %s: %w", url, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
		}

		return resp, nil
	}

	resp, err := backoff.Retry(ctx, operation,
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(5*time.Second),
	)
	if err != nil {
		return "", err
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

func chooseBranch(ctx context.Context, cfg *csconfig.Config) (string, error) {
	// this was set from config.yaml or flag
	if cfg.Cscli.HubBranch != "" {
		log.Debugf("Hub override from config: branch '%s'", cfg.Cscli.HubBranch)
		return cfg.Cscli.HubBranch, nil
	}

	csVersion := cwversion.BaseVersion()
	if csVersion == "" {
		log.Warning("Crowdsec version is not set, using hub branch 'master'")
		return "master", nil
	}

	latest, err := lookupLatest(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve latest crowdsec version: %w", err)
	}

	if csVersion == latest {
		log.Debugf("Latest crowdsec version (%s), using hub branch 'master'", version.String())
		return "master", nil
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		log.Debugf("Your current crowdsec version seems to be a pre-release (%s), using hub branch 'master'", version.String())
		return "master", nil
	}

	log.Warnf("A new CrowdSec release is available (%s). "+
		"Your version is '%s'. Please update it to use new parsers/scenarios/collections.",
		latest, csVersion)

	return csVersion, nil
}

// HubBranch sets the branch (in cscli config) and returns its value
// It can be "master", or the branch corresponding to the current crowdsec version, or the value overridden in config/flag
func HubBranch(ctx context.Context, cfg *csconfig.Config) (string, error) {
	branch, err := chooseBranch(ctx, cfg)
	if err != nil {
		return "", err
	}

	cfg.Cscli.HubBranch = branch

	return branch, nil
}

func HubURLTemplate(cfg *csconfig.Config) string {
	return cfg.Cscli.HubURLTemplate
}
