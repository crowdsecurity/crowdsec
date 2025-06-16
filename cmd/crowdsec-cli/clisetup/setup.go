package clisetup

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/AlecAivazis/survey/v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
)

type configGetter func() *csconfig.Config

type cliSetup struct {
	cfg configGetter
}

func New(cfg configGetter) *cliSetup {
	return &cliSetup{
		cfg: cfg,
	}
}


func (cli *cliSetup) setup(ctx context.Context, interactive bool) error {

	// XXX: TODO: check if anything (collections, acquisitions, parsers, scenarios) is already installed
	// if so, return if interactive is false - and change the first option

	detect := true
	if interactive {
		prompt := survey.Confirm{
			Message: "Detect and configure services?",
			Default: true,
		}

		if err := survey.AskOne(&prompt, &detect); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stdout)

	if !detect {
		fmt.Println("Quitting crowdsec configuration.")
		fmt.Println("You can always run 'crowdsec setup' later.")
		return nil
	}

	defaultServiceDetect := csconfig.DefaultConfigPath("hub", "detect.yaml")

	detectReader, err := os.Open(defaultServiceDetect)
	if err != nil {
		return err
	}

	stup, err := setup.NewSetup(detectReader, setup.DetectOptions{})
	if err != nil {
		return err
	}

	if interactive {
		svcDetected := stup.DetectedServices()
		svcSelected := []string{}

		prompt := &survey.MultiSelect{
			Message: "Confirm the services to configure. Excluding them will skip the related scenarios and log acquisition.\n",
			Options: svcDetected,
			Default: svcDetected,
		}

		err := survey.AskOne(prompt, &svcSelected)
		if err != nil {
			return err
		}

		svcFiltered := []setup.ServiceSetup{}
		for _, svc := range stup.Setup {
			if slices.Contains(svcSelected, svc.DetectedService) {
				svcFiltered = append(svcFiltered, svc)
			}
		}

		stup.Setup = svcFiltered
	} else {
		fmt.Println("The following services will be configured.")
		for _, svc := range stup.DetectedServices() {
			fmt.Printf("- %s\n", svc)
		}
	}

	fmt.Fprintln(os.Stdout)

	if err := cli.install(ctx, interactive, false, stup); err != nil {
		return err
	}

	// XXX: TODO: only if something needs installing
	installAcquis := true
	if interactive {
		prompt := survey.Confirm{
			Message: "Generate acquisition configuration?",
			Default: true,
		}

		if err := survey.AskOne(&prompt, &installAcquis); err != nil {
			return err
		}
	}

	if installAcquis {
		acquisDir := cli.cfg().Crowdsec.AcquisitionDirPath
		if err := cli.dataSources(stup, acquisDir); err != nil {
			return err
		}
	}

	return nil
}

func (cli *cliSetup) NewCommand() *cobra.Command {
	var auto bool

	cmd := &cobra.Command{
		Use:               "setup",
		// XXX: TODO: better description
		Short:             "Tools to configure crowdsec",
		Long:              "Manage hub configuration and service detection",
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		// XXX: TODO: examples!
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.setup(cmd.Context(), !auto)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&auto, "auto", false, "Unattended setup -- automatically detect services and generate configuration.")

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newDataSourcesCmd())
	cmd.AddCommand(cli.newValidateCmd())

	return cmd
}
