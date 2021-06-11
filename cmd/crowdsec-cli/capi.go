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
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"gopkg.in/yaml.v2"
)

var CAPIURLPrefix string = "v2"
var CAPIBaseURL string = "https://api.crowdsec.net/"

func NewCapiCmd() *cobra.Command {
	var cmdCapi = &cobra.Command{
		Use:   "capi [action]",
		Short: "Manage interaction with Central API (CAPI)",
		Args:  cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("no configuration for crowdsec API in '%s'", *csConfig.FilePath)
			}

			return nil
		},
	}

	var cmdCapiRegister = &cobra.Command{
		Use:   "register",
		Short: "Register to Central API (CAPI)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			id, err := generateID()
			if err != nil {
				log.Fatalf("unable to generate machine id: %s", err)
			}
			password := strfmt.Password(generatePassword(passwordLength))
			apiurl, err := url.Parse(CAPIBaseURL)
			if err != nil {
				log.Fatalf("unable to parse api url %s : %s", CAPIBaseURL, err)
			}
			_, err = apiclient.RegisterClient(&apiclient.Config{
				MachineID:     id,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiurl,
				VersionPrefix: CAPIURLPrefix,
			}, nil)

			if err != nil {
				log.Fatalf("api client register ('%s'): %s", CAPIBaseURL, err)
			}
			log.Printf("Successfully registered to Central API (CAPI)")

			var dumpFile string

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
				URL:      CAPIBaseURL,
			}
			apiConfigDump, err := yaml.Marshal(apiCfg)
			if err != nil {
				log.Fatalf("unable to marshal api credentials: %s", err)
			}
			if dumpFile != "" {
				err = ioutil.WriteFile(dumpFile, apiConfigDump, 0600)
				if err != nil {
					log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
				}
				log.Printf("Central API credentials dumped to '%s'", dumpFile)
			} else {
				fmt.Printf("%s\n", string(apiConfigDump))
			}

			log.Warningf(ReloadMessage())
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

			if csConfig.API.Server.OnlineClient.Credentials == nil {
				log.Fatalf("no credentials for crowdsec API in '%s'", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			}

			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiurl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("parsing api url ('%s'): %s", csConfig.API.Server.OnlineClient.Credentials.URL, err)
			}

			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err.Error())
			}
			if len(scenarios) == 0 {
				log.Fatalf("no scenarios installed, abort")
			}

			Client, err = apiclient.NewDefaultClient(apiurl, CAPIURLPrefix, fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()), nil)
			if err != nil {
				log.Fatalf("init default client: %s", err)
			}
			t := models.WatcherAuthRequest{
				MachineID: &csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:  &password,
				Scenarios: scenarios,
			}
			log.Infof("Loaded credentials from %s", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			log.Infof("Trying to authenticate with username %s on %s", csConfig.API.Server.OnlineClient.Credentials.Login, apiurl)
			resp, err := Client.Auth.AuthenticateWatcher(context.Background(), t)
			if err != nil {
				log.Fatalf("Failed to authenticate to Central API (CAPI) : %s", err)
			} else {
				log.Infof("You can successfully interact with Central API (CAPI)")
			}
			for k, v := range resp.Response.Header {
				log.Debugf("[headers] %s : %s", k, v)
			}
			dump, _ := httputil.DumpResponse(resp.Response, true)
			log.Debugf("Response: %s", string(dump))
		},
	}
	cmdCapi.AddCommand(cmdCapiStatus)

	cmdEnroll := &cobra.Command{
		Use:   "enroll-to-bo [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: "cscli enroll-to-bo YOUR-ENROLL-KEY",
		Args:    cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("no configuration for crowdsec API in '%s'", *csConfig.FilePath)
			}
			if csConfig.API.Server.OnlineClient.Credentials == nil {
				log.Fatal("You must configure CAPI with `cscli capi register` before enrolling your instance")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiURL, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("Could not parse CAPI URL : %s", err)
			}

			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}

			scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err.Error())
			}

			if len(scenarios) == 0 {
				scenarios = make([]string, 0)
			}

			c, _ := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:      password,
				Scenarios:     scenarios,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v2",
			})
			_, err = c.Auth.EnrollWatcher(context.Background(), args[0])
			if err != nil {
				log.Fatalf("Could not enroll instance: %s", err)
			}
			log.Infof("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
		},
	}

	cmdCapi.AddCommand(cmdEnroll)
	return cmdCapi
}
