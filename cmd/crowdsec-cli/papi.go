package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type PapiPermCheckError struct {
	Error string `json:"error"`
}

type PapiPermCheckSuccess struct {
	Status     string   `json:"status"`
	Plan       string   `json:"plan"`
	Categories []string `json:"categories"`
}

func NewPapiCmd() *cobra.Command {
	var cmdLapi = &cobra.Command{
		Use:               "papi [action]",
		Short:             "Manage interaction with Polling API (PAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				return errors.Wrap(err, "Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("no configuration for Central API in '%s'", *csConfig.FilePath)
			}
			if csConfig.API.Server.OnlineClient.Credentials.PapiURL == "" {
				log.Fatalf("no PAPI URL in configuration")
			}
			return nil
		},
	}

	cmdLapi.AddCommand(NewPapiStatusCmd())
	cmdLapi.AddCommand(NewPapiSyncCmd())

	return cmdLapi
}

func NewPapiStatusCmd() *cobra.Command {
	cmdCapiStatus := &cobra.Command{
		Use:               "status",
		Short:             "Get status of the Polling API",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {

			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			/*apiurl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("parsing api url ('%s'): %s", csConfig.API.Server.OnlineClient.Credentials.URL, err)
			}*/

			if err := csConfig.LoadHub(); err != nil {
				log.Fatal(err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Info("Run 'sudo cscli hub update' to get the hub index")
				log.Fatalf("Failed to load hub index : %s", err)
			}
			scenarios, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err)
			}
			if len(scenarios) == 0 {
				log.Fatalf("no scenarios installed, abort")
			}

			apiURL, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("parsing api url ('%s'): %s", csConfig.API.Server.OnlineClient.Credentials.URL, err)
			}
			apiClient, _ := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:      password,
				Scenarios:     scenarios,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v3",
			})

			if err != nil {
				log.Fatalf("init API client: %s", err)
			}

			papiUrl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.PapiURL)
			if err != nil {
				log.Fatalf("parsing papi url ('%s'): %s", csConfig.API.Server.OnlineClient.Credentials.PapiURL, err)
			}
			papiCheckUrl := fmt.Sprintf("%s://%s/v1/permissions", papiUrl.Scheme, papiUrl.Host)
			req, err := http.NewRequest("GET", papiCheckUrl, nil)
			if err != nil {
				log.Fatalf("failed to create request : %s", err)
			}

			httpClient := apiClient.GetClient()

			resp, err := httpClient.Do(req)
			if err != nil {
				log.Fatalf("failed to get response : %s", err)
			}

			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				errResp := PapiPermCheckError{}
				err = json.NewDecoder(resp.Body).Decode(&errResp)
				if err != nil {
					log.Fatalf("failed to decode response : %s", err)
				}
				log.Fatalf("unable to query PAPI : %s (%d)", errResp.Error, resp.StatusCode)
			}
			log.Infof("You can successfully interact with Polling API (PAPI)")
			respBody := PapiPermCheckSuccess{}
			err = json.NewDecoder(resp.Body).Decode(&respBody)
			if err != nil {
				log.Fatalf("failed to decode response : %s", err)
			}
			log.Infof("Console plan : %s", respBody.Plan)
			log.Infof("Categories subscriptions:")
			for _, cat := range respBody.Categories {
				log.Infof("  - %s", cat)
			}

		},
	}

	return cmdCapiStatus
}

func NewPapiSyncCmd() *cobra.Command {
	cmdCapiSync := &cobra.Command{
		Use:               "sync",
		Short:             "Sync with the Polling API",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			dbClient, err := database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to initialize database client : %s", err)
			}

			apiClient, err := apiserver.NewAPIC(csConfig.API.Server.OnlineClient, dbClient, csConfig.API.Server.ConsoleConfig)
			if err != nil {
				log.Fatalf("unable to initialize API client : %s", err)
			}

			papiclient, err := apiserver.NewPAPI(apiClient, dbClient, csConfig.API.Server.ConsoleConfig, log.InfoLevel)
			if err != nil {
				log.Fatalf("unable to initialize PAPI client : %s", err)
			}

			ticker := time.NewTicker(10 * time.Second)

			for {
				select {
				case <-ticker.C:
					papiclient.Client.Stop()
				}
			}
			papiclient.Client.Start(time.Time{})

		},
	}

	return cmdCapiSync
}
