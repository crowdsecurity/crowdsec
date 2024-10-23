package clihubtest

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) newInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "info",
		Short:             "info [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("unable to load test '%s': %w", testName, err)
				}
				fmt.Println()
				fmt.Printf("  Test name                   :  %s\n", test.Name)
				fmt.Printf("  Test path                   :  %s\n", test.Path)
				if isAppsecTest {
					fmt.Printf("  Nuclei Template             :  %s\n", test.Config.NucleiTemplate)
					fmt.Printf("  Appsec Rules                  :  %s\n", strings.Join(test.Config.AppsecRules, ", "))
				} else {
					fmt.Printf("  Log file                    :  %s\n", filepath.Join(test.Path, test.Config.LogFile))
					fmt.Printf("  Parser assertion file       :  %s\n", filepath.Join(test.Path, hubtest.ParserAssertFileName))
					fmt.Printf("  Scenario assertion file     :  %s\n", filepath.Join(test.Path, hubtest.ScenarioAssertFileName))
				}
				fmt.Printf("  Configuration File          :  %s\n", filepath.Join(test.Path, "config.yaml"))
			}

			return nil
		},
	}

	return cmd
}
