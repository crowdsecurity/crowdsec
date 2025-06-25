package clisetup

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
)

func (cli *cliSetup) newInstallAcquisitionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "install-acquisition [setup_file] [target-dir]",
		Short:             "generate log acquisition configuration (datasources) from a setup file",
		Args:              args.ExactArgs(2),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputReader, err := maybeStdinFile(args[0])
			if err != nil {
				return err
			}

			toDir := args[1]

			if toDir == "" {
				return errors.New("target directory cannot be empty")
			}

			stup, err := setup.NewSetupFromYAML(inputReader, true, cli.cfg().Cscli.Color != "no")
			if err != nil {
				return err
			}

			return cli.acquisition(stup.CollectAcquisitionSpecs(), toDir)
		},
	}

	return cmd
}

func (cli *cliSetup) acquisition(acquisitionSpecs []setup.AcquisitionSpec, toDir string) error {
	for _, spec := range acquisitionSpecs {
		if spec.Datasource == nil {
			continue
		}

		path, err := spec.Path(toDir)
		if err != nil {
			return err
		}

		fmt.Println("creating " + path)

		if err := spec.WriteTo(toDir); err != nil {
			return err
		}
	}

	return nil
}
