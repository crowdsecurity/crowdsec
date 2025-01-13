package clilapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const LAPIURLPrefix = "v1"

// queryLAPIStatus checks if the Local API is reachable, and if the credentials are correct.
func queryLAPIStatus(ctx context.Context, hub *cwhub.Hub, credURL string, login string, password string) (bool, error) {
	apiURL, err := url.Parse(credURL)
	if err != nil {
		return false, err
	}

	client, err := apiclient.NewDefaultClient(apiURL,
		LAPIURLPrefix,
		"",
		nil)
	if err != nil {
		return false, err
	}

	pw := strfmt.Password(password)

	itemsForAPI := hub.GetInstalledListForAPI()

	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &pw,
		Scenarios: itemsForAPI,
	}

	_, _, err = client.Auth.AuthenticateWatcher(ctx, t)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (cli *cliLapi) Status(ctx context.Context, out io.Writer, hub *cwhub.Hub) error {
	cfg := cli.cfg()

	cred := cfg.API.Client.Credentials

	fmt.Fprintf(out, "Loaded credentials from %s\n", cfg.API.Client.CredentialsFilePath)
	fmt.Fprintf(out, "Trying to authenticate with username %s on %s\n", cred.Login, cred.URL)

	_, err := queryLAPIStatus(ctx, hub, cred.URL, cred.Login, cred.Password)
	if err != nil {
		return fmt.Errorf("failed to authenticate to Local API (LAPI): %w", err)
	}

	fmt.Fprintf(out, "You can successfully interact with Local API (LAPI)\n")

	return nil
}

// prepareAPIURL checks/fixes a LAPI connection url (http, https or socket) and returns an URL struct
func prepareAPIURL(clientCfg *csconfig.LocalApiClientCfg, apiURL string) (*url.URL, error) {
	if apiURL == "" {
		if clientCfg == nil || clientCfg.Credentials == nil || clientCfg.Credentials.URL == "" {
			return nil, errors.New("no Local API URL. Please provide it in your configuration or with the -u parameter")
		}

		apiURL = clientCfg.Credentials.URL
	}

	// URL needs to end with /, but user doesn't care
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}

	// URL needs to start with http://, but user doesn't care
	if !strings.HasPrefix(apiURL, "http://") && !strings.HasPrefix(apiURL, "https://") && !strings.HasPrefix(apiURL, "/") {
		apiURL = "http://" + apiURL
	}

	return url.Parse(apiURL)
}

func (cli *cliLapi) newStatusCmd() *cobra.Command {
	cmdLapiStatus := &cobra.Command{
		Use:               "status",
		Short:             "Check authentication to Local API (LAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hub, err := require.Hub(cli.cfg(), nil)
			if err != nil {
				return err
			}

			return cli.Status(cmd.Context(), color.Output, hub)
		},
	}

	return cmdLapiStatus
}
