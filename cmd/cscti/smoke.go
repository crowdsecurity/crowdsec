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

type cliSmoke struct {}

func NewCLISmoke() *cliSmoke {
	return &cliSmoke{}
}

func (cli *cliSmoke) smoke() error {
	// check if CTI_API_KEY is set
	apiKey := os.Getenv("CTI_API_KEY")
	if apiKey == "" {
		return ErrorNoAPIKey
	}

	// create a new CTI client
	client, err := cti.NewClientWithResponses("https://cti.api.crowdsec.net/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(apiKey)))
	if err != nil {
		return err
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	resp, err := client.GetSmokeWithResponse(ctx, &cti.GetSmokeParams{})
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

func (cli *cliSmoke) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "smoke",
		Short: "Query the smoke data",
		RunE:  func(cmd *cobra.Command, args []string) error {
			return cli.smoke()
		},
	}

	return cmd
}
