package clisetup

import (
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
	"github.com/spf13/cobra"
)

type acquisitionFlags struct {
	acquisDir string
}

func (f *acquisitionFlags) bind(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.acquisDir, "acquis-dir", "", "Directory for the acquisition configuration")
}

func (cli *cliSetup) newInstallAcquisitionCmd() *cobra.Command {
	var dryRun bool

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

			builder := setup.NewSetupBuilder()

			stup, err := builder.FromYAML(inputReader, true, cli.cfg().Cscli.Color != "no")
			if err != nil {
				return err
			}

			return cli.acquisition(stup.CollectAcquisitionSpecs(), f.acquisDir, dryRun)
		},
	}

	f.bind(cmd)

	flags := cmd.Flags()
	flags.BoolVar(&dryRun, "dry-run", false, "don't install anything; print out what would have been")

	return cmd
}

func (cli *cliSetup) acquisition(acquisitionSpecs []setup.AcquisitionSpec, toDir string, dryRun bool) error {
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

		if dryRun {
			fmt.Fprintln(os.Stdout, "(dry run) "+path)
			continue
		}

		fmt.Fprintln(os.Stdout, "creating "+path)

		writer, err := spec.Open(toDir)
		if err != nil {
			return err
		}
		defer writer.Close()

		if err := spec.Write(writer); err != nil {
			return fmt.Errorf("writing acquisition to %q: %w", path, err)
		}
	}

	return nil
}
