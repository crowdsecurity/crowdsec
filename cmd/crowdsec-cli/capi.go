package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http/httputil"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"gopkg.in/yaml.v2"
)

var APIBaseURL string = "https://api.dev.crowdsec.net/"
var APIURLPrefix string = "v2"

func NewCapiCmd() *cobra.Command {
	var cmdCapi = &cobra.Command{
		Use:   "capi [action]",
		Short: "Manage interraction with Central API (CAPI)",
		Args:  cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			apiclient.BaseURL, err = url.Parse(APIBaseURL)
			if err != nil {
				return errors.Wrapf(err, "unable to parse api url %s", APIBaseURL)
			}
			apiclient.URLPrefix = APIURLPrefix
			apiclient.UserAgent = fmt.Sprintf("crowdsec/%s", cwversion.VersionStr())
			return nil
		},
	}

	var cmdCapiRegister = &cobra.Command{
		Use:   "register",
		Short: "Register to Central API (CAPI)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			Client = apiclient.NewClient(nil)

			id, err := generateID()
			if err != nil {
				log.Fatalf("unable to generate machine id: %s", err)
			}
			log.Printf("your machine ID : %s", id)
			password := strfmt.Password(generatePassword(passwordLength))
			log.Printf("your password : %s", password)
			_, err = Client.Auth.RegisterWatcher(context.Background(), models.WatcherRegistrationRequest{
				MachineID: &id,
				Password:  &password,
			})
			if err != nil {
				log.Errorf("unable to register to API (%s) : %s", Client.BaseURL, err)
			}
			log.Printf("Successfully registered to Central API (CAPI)")

			var dumpFile string

			log.Printf("config : %s", spew.Sdump(csConfig.API.Server))
			if outputFile != "" {
				dumpFile = outputFile
			} else if csConfig.API.Server.OnlineClient.CredentialsFilePath != "" {
				dumpFile = csConfig.API.Server.OnlineClient.CredentialsFilePath
			} else {
				dumpFile = ""
			}
			apiCfg := csconfig.ApiCredentialsCfg{
				Login:    id,
				Password: password.String(),
				URL:      APIBaseURL,
			}
			apiConfigDump, err := yaml.Marshal(apiCfg)
			if err != nil {
				log.Fatalf("unable to marshal api credentials: %s", err)
			}
			if dumpFile != "" {
				err = ioutil.WriteFile(dumpFile, apiConfigDump, 0644)
				if err != nil {
					log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
				}
				log.Printf("API credentials dumped to '%s'", dumpFile)
			} else {
				fmt.Printf("%s\n", string(apiConfigDump))
			}

			log.Warningf("Run 'systemctl reload crowdsec' for the new configuration to be effective")
		},
	}
	cmdCapiRegister.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmdCapi.AddCommand(cmdCapiRegister)

	var cmdCapiStatus = &cobra.Command{
		Use:   "status",
		Short: "Check status with the Central API (CAPI)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if csConfig.API.Server == nil {
				log.Fatalln("There is no configuration on 'api_client:'")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("Please provide credentials for the API in '%s'", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			}
			apiclient.BaseURL, err = url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("failed to parse Local API URL %s : %v ", csConfig.API.Server.OnlineClient.Credentials.URL, err.Error())
			}
			apiclient.UserAgent = fmt.Sprintf("crowdsec/%s", cwversion.VersionStr())
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err.Error())
			}
			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			t := models.WatcherAuthRequest{
				MachineID: &csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:  &password,
				Scenarios: scenarios,
			}
			Client = apiclient.NewClient(nil)
			resp, err := Client.Auth.AuthenticateWatcher(context.Background(), t)
			if err != nil {
				log.Errorf("Failed to authenticate to Central API (CAPI) : %s", err)
				log.Errorf("Your configuration is in %s", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			}
			for k, v := range resp.Response.Header {
				log.Printf("[headers] %s : %s", k, v)
			}
			dump, _ := httputil.DumpResponse(resp.Response, true)
			log.Infof("Body: %s", string(dump))
			log.Infof("Body-X: %s", resp.Response.Body)

		},
	}
	cmdCapi.AddCommand(cmdCapiStatus)

	return cmdCapi
}
