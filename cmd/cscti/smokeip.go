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

	switch {
	case resp.JSON404 != nil:
		return fmt.Errorf("ip not found")
	case resp.JSON403 != nil:
		return fmt.Errorf("forbidden")
	case resp.JSON500 != nil:
		return fmt.Errorf("internal server error")
	case resp.JSON429 != nil:
		return fmt.Errorf("too many requests")
	case resp.JSON400 != nil:
		return fmt.Errorf("bad request")
	case resp.JSON200 == nil:
		return fmt.Errorf("unexpected error %d", resp.StatusCode())
	}

	ctiObj := resp.JSON200

	var out []byte

	// re-encode (todo: yaml, human)

	out, err = json.MarshalIndent(ctiObj, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(out))

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
