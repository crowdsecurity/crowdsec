package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func AuthenticatedLAPIClient(ctx context.Context, credentials csconfig.ApiCredentialsCfg, hub *cwhub.Hub) (*apiclient.ApiClient, error) {
	apiURL, err := url.Parse(credentials.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing api url ('%s'): %w", credentials.URL, err)
	}

	papiURL, err := url.Parse(credentials.PapiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing polling api url ('%s'): %w", credentials.PapiURL, err)
	}

	password := strfmt.Password(credentials.Password)

	itemsForAPI := hub.GetInstalledListForAPI()

	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     credentials.Login,
		Password:      password,
		Scenarios:     itemsForAPI,
		URL:           apiURL,
		PapiURL:       papiURL,
		VersionPrefix: "v1",
		UpdateScenario: func(_ context.Context) ([]string, error) {
			return itemsForAPI, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new client api: %w", err)
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(ctx, models.WatcherAuthRequest{
		MachineID: &credentials.Login,
		Password:  &password,
		Scenarios: itemsForAPI,
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
