package clihubtest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
)

func (cli *cliHubTest) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()

			if err := hubPtr.LoadAllTests(); err != nil {
				return fmt.Errorf("unable to load all tests: %w", err)
			}

			switch cfg.Cscli.Output {
			case "human":
				hubTestListTable(color.Output, cfg.Cscli.Color, hubPtr.Tests)
			case "json":
				j, err := json.MarshalIndent(hubPtr.Tests, " ", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(j))
			default:
				return errors.New("only human/json output modes are supported")
			}

			return nil
		},
	}

	return cmd
}
