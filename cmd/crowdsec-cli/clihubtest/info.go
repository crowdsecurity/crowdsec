package clihubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (*cliHubTest) newInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "info",
		Short:             "info [test_name]",
		Args:              args.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("unable to load test '%s': %w", testName, err)
				}

				fmt.Fprintln(os.Stdout)
				fmt.Fprintf(os.Stdout, "  Test name                   :  %s\n", test.Name)
				fmt.Fprintf(os.Stdout, "  Test path                   :  %s\n", test.Path)

				if isAppsecTest {
					fmt.Fprintf(os.Stdout, "  Nuclei Template             :  %s\n", test.Config.NucleiTemplate)
					fmt.Fprintf(os.Stdout, "  Appsec Rules                  :  %s\n", strings.Join(test.Config.AppsecRules, ", "))
				} else {
					fmt.Fprintf(os.Stdout, "  Log file                    :  %s\n", filepath.Join(test.Path, test.Config.LogFile))
					fmt.Fprintf(os.Stdout, "  Parser assertion file       :  %s\n", filepath.Join(test.Path, hubtest.ParserAssertFileName))
					fmt.Fprintf(os.Stdout, "  Scenario assertion file     :  %s\n", filepath.Join(test.Path, hubtest.ScenarioAssertFileName))
				}

				fmt.Fprintf(os.Stdout, "  Configuration File          :  %s\n", filepath.Join(test.Path, "config.yaml"))
			}

			return nil
		},
	}

	return cmd
}
