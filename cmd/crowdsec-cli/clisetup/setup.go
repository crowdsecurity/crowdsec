package clisetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/AlecAivazis/survey/v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
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
	cfg := cli.cfg()

	if err := require.Agent(cfg); err != nil {
		return err
	}

	acquisFiles := cfg.Crowdsec.AcquisitionFiles

	// XXX: TODO: filter out the _generated_ files
	if len(acquisFiles) != 0 {
		fmt.Fprintln(os.Stdout, "Found the following acquisition files:")

		for _, f := range acquisFiles {
			fmt.Fprintln(os.Stdout, " - " + f)
		}
	}

	// XXX: TODO: review all prompts, cli help, examples, etc.

	// XXX: TODO: agent configuration vs lapi?
	// what if agent is disabled?
	
	// XXX: TODO: reuse or re-implement part of LoadAcquisition to collect the list of acquisition files
	// then we to process them to see whether they are auto-generated or not
	// scan all document, discard empty
	// check for comments inside

	// XXX: TODO: if some acquisition is already defined:
	//   interactive == false -> skip detect+install
	//   interactive == true -> change messages/prompt?

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

	defaultServiceDetect := csconfig.DefaultConfigPath("detect.yaml")

	detectReader, err := os.Open(defaultServiceDetect)
	if err != nil {
		return err
	}

	detector, err := setup.NewDetector(detectReader)
	if err != nil {
		return err
	}

	stup, err := setup.NewSetup(detector, setup.DetectOptions{})
	if err != nil {
		return err
	}

	svcDetected := stup.DetectedServices()

	switch {
	case len(svcDetected) == 0:
		fmt.Fprintln(os.Stdout, "No services detected.")
		return nil
	case interactive:
		svcSelected := []string{}

		prompt := &survey.MultiSelect{
			Message: "Please confirm the services to configure. Excluding them will skip the related scenarios and log acquisition.\n",
			Options: svcDetected,
			Default: svcDetected,
		}

		err := survey.AskOne(prompt, &svcSelected)
		if err != nil {
			return err
		}

		svcFiltered := []setup.ServicePlan{}
		for _, svc := range stup.Plans {
			if slices.Contains(svcSelected, svc.Name) {
				svcFiltered = append(svcFiltered, svc)
			}
		}

		stup.Plans = svcFiltered
	default:
		fmt.Println("The following services will be configured:")
		for _, svc := range svcDetected {
			fmt.Printf("- %s\n", svc)
		}
	}

	fmt.Fprintln(os.Stdout)

	hubSpecs := stup.CollectHubSpecs()

	if len(hubSpecs) > 0 {
		if err = cli.install(ctx, interactive, false, hubSpecs); err != nil {
			return err
		}

		fmt.Fprintln(os.Stdout)
	}

	acquisitionSpecs := stup.CollectAcquisitionSpecs()

	if len(acquisitionSpecs) > 0 {
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

		// XXX TODO: warn user not to alter the generated files
		// XXX TODO: and they are responsible to remove them and
		// the collections when removing the associated software
		if installAcquis {
			acquisDir := cli.cfg().Crowdsec.AcquisitionDirPath
			if err := cli.acquisition(acquisitionSpecs, acquisDir); err != nil {
				return err
			}
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
			err := cli.setup(cmd.Context(), !auto)
			if  errors.Is(err, hubops.ErrUserCanceled) {
				fmt.Fprintln(os.Stdout, err.Error())
				fmt.Println("You can always run 'crowdsec setup' later.")
				return nil
			}

			return err
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&auto, "auto", false, "Unattended setup -- automatically detect services and generate configuration")

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newAcquisitionCmd())
	cmd.AddCommand(cli.newValidateCmd())

	return cmd
}
