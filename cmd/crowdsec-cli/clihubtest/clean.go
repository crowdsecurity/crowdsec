package clihubtest

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliHubTest) newCleanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "clean",
		Short:             "clean [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("unable to load test '%s': %w", testName, err)
				}
				if err := test.Clean(); err != nil {
					return fmt.Errorf("unable to clean test '%s' env: %w", test.Name, err)
				}
			}

			return nil
		},
	}

	return cmd
}
