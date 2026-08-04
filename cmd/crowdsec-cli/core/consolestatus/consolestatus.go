// Package consolestatus fetches the live state of an engine's link to the CrowdSec
// console (CAPI/PAPI): enrollment, plan, and decision-management state.
package consolestatus

import (
	"context"
	"fmt"
	"net/url"

	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// CAPIStatus is what an authentication round-trip to CAPI tells us about the engine.
type CAPIStatus struct {
	Authenticated    bool
	Enrolled         bool
	SubscriptionType string
}

// PAPIInfo is the plan detail exposed by the PAPI /permissions endpoint plus the
// timestamp of the last order the engine pulled.
type PAPIInfo struct {
	Plan       string
	Categories []string
	LastOrder  string
}

// DecisionManagementActive reports whether the console pushes decisions to this
// engine, from PAPI.
func DecisionManagementActive(subscriptionType string) bool {
	return subscriptionType == apiclient.SubscriptionTypeEnterprise ||
		subscriptionType == apiclient.SubscriptionTypeSecOps
}

// QueryCAPIStatus authenticates against the Central API
// and reads enrollment and subscription type from the returned JWT.
func QueryCAPIStatus(ctx context.Context, db *database.Client, hub *cwhub.Hub, credURL string, login string, password string) (CAPIStatus, error) {
	apiURL, err := url.Parse(credURL)
	if err != nil {
		return CAPIStatus{}, err
	}

	itemsForAPI := hub.GetInstalledListForAPI()

	passwd := strfmt.Password(password)

	client := apiclient.NewClient(&apiclient.Config{
		MachineID:     login,
		Password:      passwd,
		URL:           apiURL,
		VersionPrefix: "v3",
		UpdateScenario: func(_ context.Context) ([]string, error) {
			return itemsForAPI, nil
		},
	})

	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &passwd,
		Scenarios: itemsForAPI,
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(ctx, t)
	if err != nil {
		return CAPIStatus{}, err
	}

	if err := db.SaveAPICToken(ctx, authResp.Token); err != nil {
		return CAPIStatus{}, err
	}

	client.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token

	if client.IsEnrolled() {
		return CAPIStatus{Authenticated: true, Enrolled: true, SubscriptionType: client.GetSubscriptionType()}, nil
	}

	return CAPIStatus{Authenticated: true}, nil
}

// QueryPAPIInfo asks PAPI for the plan/categories the engine is entitled to
func QueryPAPIInfo(ctx context.Context, serverCfg *csconfig.LocalApiServerCfg, db *database.Client) (PAPIInfo, error) {
	apic, err := apiserver.NewAPIC(ctx, serverCfg.OnlineClient, db, serverCfg.ConsoleConfig, serverCfg.CapiWhitelists)
	if err != nil {
		return PAPIInfo{}, fmt.Errorf("unable to initialize API client: %w", err)
	}

	papi, err := apiserver.NewPAPI(apic, db, serverCfg.ConsoleConfig, serverCfg.NewPAPILogger())
	if err != nil {
		return PAPIInfo{}, fmt.Errorf("unable to initialize PAPI client: %w", err)
	}

	perms, err := papi.GetPermissions(ctx)
	if err != nil {
		return PAPIInfo{}, fmt.Errorf("unable to get PAPI permissions: %w", err)
	}

	lastOrder, err := db.GetConfigItem(ctx, apiserver.PapiPullKey)
	if err != nil {
		lastOrder = "never"
	}

	// both can and did happen
	if lastOrder == "" || lastOrder == "0001-01-01T00:00:00Z" {
		lastOrder = "never"
	}

	return PAPIInfo{Plan: perms.Plan, Categories: perms.Categories, LastOrder: lastOrder}, nil
}
