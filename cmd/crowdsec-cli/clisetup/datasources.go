package clisetup

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

func (cli *cliSetup) newDataSourcesCmd() *cobra.Command {
	var toDir string

	cmd := &cobra.Command{
		Use:               "datasources [setup_file] [flags]",
		Short:             "generate datasource (acquisition) configuration from a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.dataSources(args[0], toDir)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&toDir, "to-dir", "", "write the configuration to a directory, in multiple files")

	return cmd
}

func (cli *cliSetup) dataSources(fromFile string, toDir string) error {
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading setup file: %w", err)
	}

	output, err := setup.DataSources(input, toDir)
	if err != nil {
		return err
	}

	if toDir == "" {
		fmt.Println(output)
	}

	return nil
}
