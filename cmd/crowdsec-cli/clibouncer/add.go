package clibouncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (cli *cliBouncers) add(ctx context.Context, bouncerName string, key string) error {
	var err error

	keyLength := 32

	if key == "" {
		key, err = middlewares.GenerateAPIKey(keyLength)
		if err != nil {
			return fmt.Errorf("unable to generate api key: %w", err)
		}
	}

	_, err = cli.db.CreateBouncer(ctx, bouncerName, "", middlewares.HashSHA512(key), types.ApiKeyAuthType, false)
	if err != nil {
		return fmt.Errorf("unable to create bouncer: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		fmt.Printf("API key for '%s':\n\n", bouncerName)
		fmt.Printf("   %s\n\n", key)
		fmt.Print("Please keep this key since you will not be able to retrieve it!\n")
	case "raw":
		fmt.Print(key)
	case "json":
		j, err := json.Marshal(key)
		if err != nil {
			return errors.New("unable to serialize api key")
		}

		fmt.Print(string(j))
	}

	return nil
}

func (cli *cliBouncers) newAddCmd() *cobra.Command {
	var key string

	cmd := &cobra.Command{
		Use:   "add MyBouncerName",
		Short: "add a single bouncer to the database",
		Example: `cscli bouncers add MyBouncerName
cscli bouncers add MyBouncerName --key <random-key>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.add(cmd.Context(), args[0], key)
		},
	}

	flags := cmd.Flags()
	flags.StringP("length", "l", "", "length of the api key")
	_ = flags.MarkDeprecated("length", "use --key instead")
	flags.StringVarP(&key, "key", "k", "", "api key for the bouncer")

	return cmd
}
