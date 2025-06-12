package clisetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

func (cli *cliSetup) newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "validate [setup_file]",
		Short:             "validate a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.validate(args[0])
		},
	}

	return cmd
}

func (cli *cliSetup) validate(fromFile string) error {
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading stdin: %w", err)
	}

	if err = setup.Validate(input); err != nil {
		fmt.Printf("%v\n", err)
		return errors.New("invalid setup file")
	}

	return nil
}
