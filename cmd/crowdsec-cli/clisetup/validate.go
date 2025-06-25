package clisetup

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
)

func (cli *cliSetup) newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "validate [setup_file]",
		Short:             "validate a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputReader, err := maybeStdinFile(args[0])
			if err != nil {
				return err
			}

			return cli.validate(inputReader)
		},
	}

	return cmd
}

func (cli *cliSetup) validate(input io.Reader) error {
	if _, err := setup.NewSetupFromYAML(input, true, cli.cfg().Cscli.Color != "no"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return errors.New("invalid setup file")
	}

	return nil
}
