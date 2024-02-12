package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func AuthenticatedLAPIClient(credentials csconfig.ApiCredentialsCfg, hub *cwhub.Hub) (*apiclient.ApiClient, error) {
	scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
	if err != nil {
		return nil, fmt.Errorf("loading list of installed hub scenarios: %w", err)
	}

	appsecRules, err := hub.GetInstalledItemNames(cwhub.APPSEC_RULES)
	if err != nil {
		return nil, fmt.Errorf("loading list of installed hub appsec rules: %w", err)
	}

	installedScenariosAndAppsecRules := make([]string, 0, len(scenarios)+len(appsecRules))
	installedScenariosAndAppsecRules = append(installedScenariosAndAppsecRules, scenarios...)
	installedScenariosAndAppsecRules = append(installedScenariosAndAppsecRules, appsecRules...)

	apiURL, err := url.Parse(credentials.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing api url ('%s'): %w", credentials.URL, err)
	}
	papiURL, err := url.Parse(credentials.PapiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing polling api url ('%s'): %w", credentials.PapiURL, err)
	}
	password := strfmt.Password(credentials.Password)

	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     credentials.Login,
		Password:      password,
		Scenarios:     installedScenariosAndAppsecRules,
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		PapiURL:       papiURL,
		VersionPrefix: "v1",
		UpdateScenario: func() ([]string, error) {
			scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
			if err != nil {
				return nil, err
			}
			appsecRules, err := hub.GetInstalledItemNames(cwhub.APPSEC_RULES)
			if err != nil {
				return nil, err
			}
			ret := make([]string, 0, len(scenarios)+len(appsecRules))
			ret = append(ret, scenarios...)
			ret = append(ret, appsecRules...)
			return ret, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new client api: %w", err)
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &credentials.Login,
		Password:  &password,
		Scenarios: installedScenariosAndAppsecRules,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticate watcher (%s): %w", credentials.Login, err)
	}

	var expiration time.Time
	if err := expiration.UnmarshalText([]byte(authResp.Expire)); err != nil {
		return nil, fmt.Errorf("unable to parse jwt expiration: %w", err)
	}

	client.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token
	client.GetClient().Transport.(*apiclient.JWTTransport).Expiration = expiration

	return client, nil
}
