package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cti"
)

type cliSmokeIP struct {}

func NewCLISmokeIP() *cliSmokeIP {
	return &cliSmokeIP{}
}

func (cli *cliSmokeIP) smokeip(ip string) error {
	// check if CTI_API_KEY is set
	apiKey := os.Getenv("CTI_API_KEY")
	if apiKey == "" {
		return ErrorNoAPIKey
	}

	provider, err := cti.NewAPIKeyProvider(apiKey)
	if err != nil {
		return err
	}

	// create a new CTI client
	client, err := cti.NewClientWithResponses("https://cti.api.crowdsec.net/v2/", cti.WithRequestEditorFn(provider.Intercept))
	if err != nil {
		return err
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	resp, err := client.GetSmokeIpWithResponse(ctx, ip)
	if err != nil {
		return err
	}

	if resp.JSON200 != nil {
		out, err := json.MarshalIndent(resp.JSON200, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	}

	return nil
}

func (cli *cliSmokeIP) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "smoke-ip",
		Short: "Query the smoke data with a given IP",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error {
			return cli.smokeip(args[0])
		},
	}

	return cmd
}
