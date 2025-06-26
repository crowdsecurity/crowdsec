package clisetup

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
)

type acquisitionFlags struct {
	acquisDir string
}

func (f *acquisitionFlags) bind(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.acquisDir, "acquis-dir", "", "Directory for the acquisition configuration")
}

func (cli *cliSetup) newInstallAcquisitionCmd() *cobra.Command {
	f := acquisitionFlags{}

	cmd := &cobra.Command{
		Use:               "install-acquisition [setup_file]",
		Short:             "generate log acquisition configuration (datasources) from a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputReader, err := maybeStdinFile(args[0])
			if err != nil {
				return err
			}

			stup, err := setup.NewSetupFromYAML(inputReader, true, cli.cfg().Cscli.Color != "no")
			if err != nil {
				return err
			}

			return cli.acquisition(stup.CollectAcquisitionSpecs(), f.acquisDir)
		},
	}

	f.bind(cmd)

	return cmd
}

func (cli *cliSetup) acquisition(acquisitionSpecs []setup.AcquisitionSpec, toDir string) error {
	for _, spec := range acquisitionSpecs {
		if spec.Datasource == nil {
			continue
		}

		cfg := cli.cfg()

		if toDir == "" {
			toDir = cfg.Crowdsec.AcquisitionDirPath
		}
		
		if toDir == "" {
			return fmt.Errorf("no acquisition directory specified, please use --acquis-dir or set crowdsec_services.acquisition_path in %q", cfg.FilePath)
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
