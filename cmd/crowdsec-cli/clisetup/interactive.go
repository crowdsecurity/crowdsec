package clisetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
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
# prompt the user for confirmation at each step
cscli setup interactive

# write acquisition files to a specific directory
cscli setup interactive --acquis-dir /path/to/acquis.d

# use a different set of detection rules
cscli setup interactive --detect-config /path/to/detact.yaml
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			detectConfig, _, err := df.detectConfig()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			err = cli.wizard(cmd.Context(), detectConfig, df.toDetectOptions(logger), af.acquisDir, true, dryRun, logger)
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
