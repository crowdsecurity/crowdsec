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

// unattendedDisabled reports whether unattended setup should be skipped.
// Any non-empty value of CROWDSEC_SETUP_UNATTENDED_DISABLE disables it.
func unattendedDisabled() bool {
	v, ok := os.LookupEnv("CROWDSEC_SETUP_UNATTENDED_DISABLE")
	return ok && v != ""
}

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

CROWDSEC_SETUP_UNATTENDED_DISABLE
    If this variable is set to a non-empty value, unattended setup will be skipped.
    This can be useful with ansible or other automation tools.
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			detectConfig, _, err := df.detectConfig()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			if unattendedDisabled() {
				fmt.Fprintln(os.Stdout, "Unattended setup is disabled (CROWDSEC_SETUP_UNATTENDED_DISABLE is set).")
				fmt.Fprintln(os.Stdout, "No collection or acquisition file will be generated now. At least an acquisition will be required to run crowdsec.")
				return nil
			}

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
