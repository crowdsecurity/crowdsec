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

func (cli *cliSetup) newInteractiveCmd() *cobra.Command {
	df := detectFlags{}
	af := acquisitionFlags{}

	var dryRun bool

	cmd := &cobra.Command{
		Use:   "interactive",
		Short: "Interactive setup",
		Long:  "Detect services and generate configuration, with user prompts",
		Example: `# Detect running services, install the appropriate collections and acquisition configuration.
# Prompt the user for confirmation at each step.
cscli setup interactive

# Write the acquisition configuration to a specific directory.
cscli setup interactive --acquis-dir /path/to/acquis.d

# Use a different detection configuration file.
cscli setup interactive --detect-config /path/to/detact.yaml

# Force the OS to be detected as 'ubuntu 25.04'
cscli setup interactive --force-os-family linux --force-os-id ubuntu --force-os-version 25.04
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			detector, _, err := df.detector()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			err = cli.wizard(cmd.Context(), detector, df.toDetectOptions(logger), af.acquisDir, true, dryRun, logger)
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
