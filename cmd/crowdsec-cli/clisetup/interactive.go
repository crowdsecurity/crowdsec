package clisetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/hubops"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
)

func (cli *cliSetup) newInteractiveCmd() *cobra.Command {
	df := detectFlags{}
	af := acquisitionFlags{}

	cmd := &cobra.Command{
		Use:               "interactive",
		Short:             "Interactive setup",
		Long:              "Detect services and generate configuration, with user prompts",
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		// XXX: TODO: examples!
		RunE: func(cmd *cobra.Command, _ []string) error {
			detector, _, err := df.detector()
			if err != nil {
				return err
			}

			logger := logrus.StandardLogger()

			err = cli.wizard(cmd.Context(), detector, df.toDetectOptions(logger), af.acquisDir, true, logger)
			if  errors.Is(err, hubops.ErrUserCanceled) {
				fmt.Fprintln(os.Stdout, err.Error())
				fmt.Println("You can always run 'crowdsec setup' later.")
				return nil
			}

			return err
		},
	}

	df.bind(cmd)
	af.bind(cmd)

	return cmd
}
