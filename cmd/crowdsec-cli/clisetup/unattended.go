package clisetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

func (cli *cliSetup) newUnattendedCmd() *cobra.Command {
	var dryRun bool

	df := detectFlags{}
	af := acquisitionFlags{}

	cmd := &cobra.Command{
		Use:   "unattended",
		Short: "Unattended setup",
		Long:  "Automatically detect services and generate configuration",
		Example: `# Detect running services, install the appropriate collections and acquisition configuration.
# Never prompt the user. Return early if the user has added to (or modified) the acquisition configuration.
cscli setup unattended

# Write the acquisition configuration to a specific directory.
cscli setup unattended --acquis-dir /path/to/acquis.d

# Use a different detection configuration file.
cscli setup unattended --detect-config /path/to/detact.yaml

# Force the OS to be detected as 'ubuntu 25.04'
cscli setup unattended --force-os-family linux --force-os-id ubuntu --force-os-version 25.04
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			detector, _, err := df.detector()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			err = cli.wizard(cmd.Context(), detector, df.toDetectOptions(logger), af.acquisDir, false, dryRun, logger)
			if errors.Is(err, hubops.ErrUserCanceled) {
				fmt.Fprintln(os.Stdout, err.Error())
				fmt.Fprintln(os.Stdout, "You can always run 'crowdsec setup' later.")
				return nil
			}

			return err
		},
	}

	df.bind(cmd)
	af.bind(cmd)

	flags := cmd.Flags()
	flags.BoolVar(&dryRun, "dry-run", false, "don't install anything; print out what would have been")

	return cmd
}
