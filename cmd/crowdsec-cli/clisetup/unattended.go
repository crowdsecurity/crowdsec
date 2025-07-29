package clisetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
# never prompt for confirmation. stop running if there are manually created acquisition files
cscli setup unattended

# write acquisition files to a specific directory
cscli setup unattended --acquis-dir /path/to/acquis.d

# use a different detection configuration file.
cscli setup unattended --detect-config /path/to/detact.yaml

# force the OS to be detected as 'ubuntu 25.04'
cscli setup unattended --force-os-family linux --force-os-id ubuntu --force-os-version 25.04
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			detectConfig, _, err := df.detectConfig()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			err = cli.wizard(cmd.Context(), detectConfig, df.toDetectOptions(logger), af.acquisDir, false, dryRun, logger)
			if errors.Is(err, hubops.ErrUserCanceled) {
				fmt.Fprintln(os.Stdout, err.Error())
				fmt.Fprintln(os.Stdout, "You can always run 'cscli setup' later.")
				return nil
			}

			return err
		},
	}

	df.bind(cmd)
	af.bind(cmd)

	flags := cmd.Flags()
	flags.BoolVar(&dryRun, "dry-run", false, "simulate the installation without making any changes")

	return cmd
}
